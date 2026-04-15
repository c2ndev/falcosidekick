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
	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/logging"
	"github.com/falcosecurity/falcosidekick/internal/metrics"
	"github.com/falcosecurity/falcosidekick/internal/outputs/all"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/version"
)

func main() {
	configPath := flag.String("c", "", "config file path")
	showVersion := flag.Bool("v", false, "print version and exit")
	flag.BoolVar(showVersion, "version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		v := version.GetInfo()
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
	v := version.GetInfo()

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}

	if errs := cfg.Validate(); len(errs) > 0 {
		return fmt.Errorf("config validation: %s", errs.Error())
	}

	logger, err := logging.NewLogger(cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	slog.SetDefault(logger)

	slog.Info("starting falcosidekick",
		"version", v.Version,
		"commit", v.Commit,
		"build_date", v.BuildDate,
		"go_version", v.GoVersion,
	)

	collector := metrics.NewCollector()

	db, err := createDatabase(cfg.Database)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	if err := db.Provision(context.Background(), &core.ProvisionRequest{
		Config:  &cfg.Config,
		Outputs: cfg.Pipeline.Outputs,
	}); err != nil {
		return fmt.Errorf("database provision: %w", err)
	}
	slog.Info("database provisioned", "backend", cfg.Database.Backend, "outputs", len(cfg.Pipeline.Outputs))

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

	srv, err := api.NewServer(&api.ServerConfig{
		Pipeline:  pipe,
		ReadStore: readStore,
		Database:  db,
		Metrics:   collector,
		Registry:  collector.Registry(),
		TLS:       cfg.TLS,
		Address:   cfg.ListenAddress,
		Port:      cfg.ListenPort,
	})
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}

	pipe.Start()

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

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	pipe.Shutdown(shutdownCtx)

	for _, out := range outputs {
		if closeErr := out.Close(); closeErr != nil {
			slog.Error("output close", "output", out.Name(), "error", closeErr)
		}
	}

	if closeErr := db.Close(); closeErr != nil {
		slog.Error("database close", "error", closeErr)
	}

	slog.Info("stopped")
	return nil
}

func resolveReadableStore(outputs []*pipeline.Output, ui core.UIConfig) (output.ReadableStore, error) {
	if !ui.Enabled || ui.EventSource == "" {
		return nil, nil
	}

	for _, out := range outputs {
		if out.Name() == ui.EventSource {
			rs, ok := out.Driver().(output.ReadableStore)
			if !ok {
				return nil, fmt.Errorf("output %q does not implement ReadableStore", ui.EventSource)
			}
			return rs, nil
		}
	}

	return nil, fmt.Errorf("ui.event_source %q not found in configured outputs", ui.EventSource)
}

func createDatabase(cfg core.DatabaseConfig) (core.Database, error) {
	switch cfg.Backend {
	case core.DatabaseInMemory:
		return database.NewMemory(), nil
	default:
		return nil, fmt.Errorf("database backend %q not implemented", cfg.Backend)
	}
}

func createOutputs(cfg *config.Config, cat *catalog.Catalog, mc core.MetricsCollector) ([]*pipeline.Output, error) {
	outputs := make([]*pipeline.Output, 0, len(cfg.Pipeline.Outputs))

	for name, outputCfg := range cfg.Pipeline.Outputs {
		driver, err := cat.Create(name, outputCfg, output.Deps{Logger: slog.Default(), Metrics: mc})
		if err != nil {
			return nil, fmt.Errorf("output %q: %w", name, err)
		}
		if err := driver.Init(context.Background()); err != nil {
			return nil, fmt.Errorf("output %q init: %w", name, err)
		}

		outCfg, err := cfg.Pipeline.ResolveOutputConfig(name)
		if err != nil {
			return nil, fmt.Errorf("output %q config: %w", name, err)
		}

		out := pipeline.NewOutput(driver, &outCfg, mc)
		outputs = append(outputs, out)
		slog.Info("output enabled", "output", name, "min_priority", outCfg.MinPriority)
	}

	return outputs, nil
}
