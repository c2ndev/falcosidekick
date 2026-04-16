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
	"github.com/falcosecurity/falcosidekick/internal/metrics"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/reload"
)

// app holds the running application resources built during startup.
type app struct {
	db          core.Database
	pipe        *pipeline.Pipeline
	srv         *api.Server
	reloader    *reload.Reloader
	listenAddr  string
	listenPort  int
	outputCount int
}

// buildApp builds all application resources. On failure, resources built
// so far are closed before returning; the caller does not need deferred cleanup.
func buildApp(
	ctx context.Context,
	cfg *config.Config,
	outsCfg *config.OutputsConfig,
	outputPaths []string,
	collector *metrics.Collector,
	cat *catalog.Catalog,
) (_ *app, retErr error) {
	db, err := createDatabase(cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = db.Close()
		}
	}()

	if err := db.Provision(ctx, &core.ProvisionRequest{
		Config:  &cfg.Config,
		Outputs: outsCfg.Outputs,
	}); err != nil {
		return nil, fmt.Errorf("database provision: %w", err)
	}
	slog.Info("database provisioned", "backend", cfg.Database.Backend, "outputs", len(outsCfg.Outputs))

	enricher, err := pipeline.NewEnricher(cfg.Enricher)
	if err != nil {
		return nil, fmt.Errorf("enricher: %w", err)
	}

	outputs, err := createOutputs(ctx, cfg, outsCfg.Outputs, cat, collector)
	if err != nil {
		return nil, fmt.Errorf("outputs: %w", err)
	}
	defer func() {
		if retErr != nil {
			closeOutputs(outputs)
		}
	}()

	dispatcher := pipeline.NewDispatcher(outputs)

	if cfg.UI.Enabled {
		if _, ok := dispatcher.GetReadableStore(cfg.UI.EventSource); !ok {
			return nil, fmt.Errorf("ui.event_source %q: output not found or does not implement ReadableStore", cfg.UI.EventSource)
		}
	}

	pipe, err := pipeline.NewPipeline(enricher, dispatcher, collector)
	if err != nil {
		return nil, fmt.Errorf("pipeline: %w", err)
	}

	srv, err := api.NewServer(&api.ServerConfig{
		Pipeline:    pipe,
		Database:    db,
		Metrics:     collector,
		Registry:    collector.Registry(),
		TLS:         cfg.TLS,
		Address:     cfg.ListenAddress,
		EventSource: cfg.UI.EventSource,
		Port:        cfg.ListenPort,
	})
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}

	reloader := reload.NewReloader(&reload.ReloaderConfig{
		OutputPaths:     outputPaths,
		Catalog:         cat,
		Dispatcher:      dispatcher,
		Database:        db,
		RuntimeDefaults: cfg.RuntimeDefaults,
		Deps:            output.Deps{Logger: slog.Default(), Metrics: collector},
		Registry:        collector.Registry(),
		Logger:          slog.Default(),
		InitialOutputs:  outsCfg.Outputs,
	})

	return &app{
		db:          db,
		pipe:        pipe,
		srv:         srv,
		reloader:    reloader,
		listenAddr:  cfg.ListenAddress,
		listenPort:  cfg.ListenPort,
		outputCount: len(outputs),
	}, nil
}

// startReloadWatchers wires the fsnotify, poller, and SIGHUP reload
// triggers. All goroutines exit when appCtx is canceled.
func (a *app) startReloadWatchers(
	appCtx, workerRunCtx context.Context,
	outputPaths []string,
	reloadCfg core.ReloadConfig,
) {
	if len(outputPaths) == 0 {
		return
	}

	reloadFn := func() error {
		return a.reloader.Reload(appCtx, workerRunCtx, reloadCfg.RetireTimeout)
	}

	watcher := reload.NewWatcher(outputPaths, 100*time.Millisecond, reloadFn, slog.Default())
	go func() {
		if err := watcher.Run(appCtx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("watcher stopped", "error", err)
		}
	}()

	if reloadCfg.PollInterval > 0 {
		poller := reload.NewPoller(outputPaths, reloadCfg.PollInterval, reloadFn, slog.Default())
		go func() {
			if err := poller.Run(appCtx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("poller stopped", "error", err)
			}
		}()
	}

	sigHUP := make(chan os.Signal, 1)
	signal.Notify(sigHUP, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-appCtx.Done():
				signal.Stop(sigHUP)
				return
			case <-sigHUP:
				slog.Info("received SIGHUP, reloading output config")
				if err := reloadFn(); err != nil {
					slog.Error("reload failed (SIGHUP)", "error", err)
				}
			}
		}
	}()
}

// serve starts the HTTP server in a background goroutine. Non-shutdown
// errors are sent to errCh. The caller owns the channel.
func (a *app) serve(errCh chan<- error) {
	go func() {
		slog.Info("listening", "address", a.listenAddr, "port", a.listenPort, "outputs", a.outputCount)
		if err := a.srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
}

// shutdown performs orderly teardown: server, pipeline, database.
func (a *app) shutdown() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := a.srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown", "error", err)
	}

	if err := a.pipe.Shutdown(shutdownCtx); err != nil {
		slog.Warn("pipeline shutdown: deadline exceeded, deferred cleanup may continue asynchronously", "error", err)
	}

	if err := a.db.Close(); err != nil {
		slog.Error("database close", "error", err)
	}

	slog.Info("stopped")
}

func createDatabase(cfg core.DatabaseConfig) (core.Database, error) {
	switch cfg.Backend {
	case core.DatabaseInMemory:
		return database.NewMemory(), nil
	default:
		return nil, fmt.Errorf("database backend %q not implemented", cfg.Backend)
	}
}

func createOutputs(
	ctx context.Context,
	cfg *config.Config,
	rawOutputs map[string]map[string]any,
	cat *catalog.Catalog,
	mc core.MetricsCollector,
) (_ []*pipeline.Output, retErr error) {
	outputs := make([]*pipeline.Output, 0, len(rawOutputs))
	defer func() {
		if retErr != nil {
			closeOutputs(outputs)
		}
	}()

	for name, outputCfg := range rawOutputs {
		driver, err := cat.Create(name, outputCfg, output.Deps{Logger: slog.Default(), Metrics: mc})
		if err != nil {
			return nil, fmt.Errorf("output %q: %w", name, err)
		}
		if err := driver.Init(ctx); err != nil {
			_ = driver.Close()
			return nil, fmt.Errorf("output %q init: %w", name, err)
		}

		outCfg, err := config.MergeRuntimeConfig(cfg.RuntimeDefaults, name, driver.RuntimeConfig())
		if err != nil {
			_ = driver.Close()
			return nil, fmt.Errorf("output %q config: %w", name, err)
		}

		out := pipeline.NewOutput(driver, &outCfg, mc)
		outputs = append(outputs, out)
		slog.Info("output enabled", "output", name, "min_priority", outCfg.MinPriority)
	}

	return outputs, nil
}

func closeOutputs(outputs []*pipeline.Output) {
	for _, out := range outputs {
		if err := out.Close(); err != nil {
			slog.Warn("output close during cleanup", "output", out.Name(), "error", err)
		}
	}
}
