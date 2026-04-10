// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/api"
	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/config"
	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/logging"
	"github.com/falcosecurity/falcosidekick/internal/metrics"
	"github.com/falcosecurity/falcosidekick/internal/outputs/all"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

func main() {
	configPath := flag.String("c", "", "config file path")
	showVersion := flag.Bool("v", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		v := GetVersionInfo()
		fmt.Printf("falcosidekick %s (commit: %s, built: %s, go: %s)\n",
			v.Version, v.Commit, v.BuildDate, v.GoVersion)
		return
	}

	if err := run(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}

	if errs := cfg.Validate(); len(errs) > 0 {
		return fmt.Errorf("config validation: %s", errs.Error())
	}

	logger, err := logging.NewLogger(logging.LogLevel(cfg.LogLevel), logging.LogFormat(cfg.LogFormat))
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	slog.SetDefault(logger)

	v := GetVersionInfo()
	slog.Info("starting falcosidekick",
		"version", v.Version,
		"commit", v.Commit,
		"build_date", v.BuildDate,
		"go_version", v.GoVersion,
	)

	collector := metrics.NewCollector()

	cat, err := catalog.New(all.Types())
	if err != nil {
		return fmt.Errorf("catalog: %w", err)
	}

	enricher, err := pipeline.NewEnricher(cfg.Pipeline.Enricher)
	if err != nil {
		return fmt.Errorf("enricher: %w", err)
	}

	outputs, err := createOutputs(cfg, cat, collector)
	if err != nil {
		return fmt.Errorf("outputs: %w", err)
	}

	readStore, err := resolveReadableStore(outputs, cfg.UI)
	if err != nil {
		return fmt.Errorf("readable store: %w", err)
	}

	dispatcher := pipeline.NewDispatcher(outputs)

	pipe, err := pipeline.NewPipeline(enricher, dispatcher, collector)
	if err != nil {
		return fmt.Errorf("pipeline: %w", err)
	}

	srv, err := api.NewServer(api.ServerConfig{
		Pipeline:  pipe,
		ReadStore: readStore,
		Metrics:   collector,
		Registry:  collector.Registry(),
		Address:   cfg.ListenAddress,
		Port:      cfg.ListenPort,
	})
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}

	// Two-context shutdown: drainCtx is parent, workerCtx is child.
	// SIGTERM -> shutdown server -> close queues (drain)
	// -> if drain timeout fires -> drainCtx canceled -> workerCtx canceled -> workers force-stop
	drainCtx, drainCancel := context.WithCancel(context.Background())
	defer drainCancel()

	workerCtx, workerCancel := context.WithCancel(drainCtx)
	defer workerCancel()

	pipe.Start(workerCtx)

	go func() {
		slog.Info("listening", "address", cfg.ListenAddress, "port", cfg.ListenPort, "outputs", len(outputs))
		if listenErr := srv.Start(); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			slog.Error("server failed", "error", listenErr)
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh

	slog.Info("shutting down")

	if shutdownErr := srv.Shutdown(); shutdownErr != nil {
		slog.Error("server shutdown", "error", shutdownErr)
	}

	drainTimeout, drainTimeoutCancel := context.WithTimeout(drainCtx, 10*time.Second)
	defer drainTimeoutCancel()
	pipe.DrainQueues(drainTimeout)

	for _, out := range outputs {
		if closeErr := out.Close(); closeErr != nil {
			slog.Error("output close", "output", out.Name(), "error", closeErr)
		}
	}

	slog.Info("stopped")
	return nil
}

func resolveReadableStore(outputs []*pipeline.Output, ui config.UIConfig) (domain.ReadableStore, error) {
	if !ui.Enabled || ui.Backend == "" {
		return nil, nil
	}

	for _, out := range outputs {
		if out.Name() == ui.Backend {
			rs, ok := out.Driver().(domain.ReadableStore)
			if !ok {
				return nil, fmt.Errorf("output %q does not implement ReadableStore", ui.Backend)
			}
			return rs, nil
		}
	}

	return nil, fmt.Errorf("ui.backend %q not found in configured outputs", ui.Backend)
}

func createOutputs(cfg *config.Config, cat *catalog.Catalog, mc domain.MetricsCollector) ([]*pipeline.Output, error) {
	outputs := make([]*pipeline.Output, 0, len(cfg.Pipeline.Outputs))

	for name, outputCfg := range cfg.Pipeline.Outputs {
		driver, err := cat.Create(name, outputCfg, domain.OutputDeps{Logger: slog.Default(), Metrics: mc})
		if err != nil {
			return nil, fmt.Errorf("output %q: %w", name, err)
		}
		if err := driver.Init(context.Background()); err != nil {
			return nil, fmt.Errorf("output %q init: %w", name, err)
		}

		outCfg := cfg.Pipeline.ResolveOutputConfig(name)

		out := pipeline.NewOutput(driver, &outCfg, mc)
		outputs = append(outputs, out)
		slog.Info("output enabled", "output", name, "min_priority", outCfg.MinPriority)
	}

	return outputs, nil
}
