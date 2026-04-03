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
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/api"
	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/config"
	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/outputs/all"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/store"
)

func main() {
	cfg, err := config.Load(os.Getenv("CONFIG_FILE"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if errs := cfg.Validate(); len(errs) > 0 {
		log.Fatalf("config validation failed: %s", errs.Error()) //nolint:gosec // G706: validation errors contain only our field names and messages
	}

	cat, err := catalog.New(all.Types())
	if err != nil {
		log.Fatalf("catalog: %v", err)
	}

	enricher, err := pipeline.NewEnricher(cfg.Pipeline.Enricher)
	if err != nil {
		log.Fatalf("enricher: %v", err)
	}

	outputPriorities := make(map[string]domain.Priority)
	activeOutputs := make([]domain.Output, 0, len(cfg.Pipeline.Outputs))

	for name, outputCfg := range cfg.Pipeline.Outputs {
		output, createErr := cat.Create(name, outputCfg, domain.OutputDeps{})
		if createErr != nil {
			log.Fatalf("output %q: %v", name, createErr)
		}
		if initErr := output.Init(context.Background()); initErr != nil {
			log.Fatalf("output %q init: %v", name, initErr)
		}
		activeOutputs = append(activeOutputs, output)

		if mp, ok := outputCfg["minimumpriority"]; ok {
			if s, ok := mp.(string); ok && s != "" {
				outputPriorities[name] = domain.Priority(s)
			}
		}
	}

	router := pipeline.NewRouter(outputPriorities)
	dispatcher := pipeline.NewDispatcher(activeOutputs, cfg.Pipeline.OutputWorkerConfig, nil)

	var eventStore domain.EventStore
	if cfg.UI.Enabled {
		eventStore = store.NewMemoryStore(cfg.EventStore.Memory)
	}

	pipe, err := pipeline.NewPipeline(
		enricher,
		eventStore,
		router,
		dispatcher,
		nil,
	)
	if err != nil {
		log.Fatalf("pipeline: %v", err)
	}

	srv, err := api.NewServer(api.ServerConfig{
		Pipeline: pipe,
		Address:  cfg.ListenAddress,
		Port:     cfg.ListenPort,
	})
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	if eventStore != nil {
		defer func() {
			if closeErr := eventStore.Close(); closeErr != nil {
				log.Printf("store close: %v", closeErr)
			}
		}()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	pipe.Start(ctx)

	go func() {
		log.Printf("falcosidekick v3 listening on %s:%d", cfg.ListenAddress, cfg.ListenPort) //nolint:gosec // config values are validated
		if listenErr := srv.Start(); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			log.Fatalf("server: %v", listenErr)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")

	if shutdownErr := srv.Shutdown(); shutdownErr != nil {
		log.Printf("server shutdown: %v", shutdownErr)
	}

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer drainCancel()
	pipe.DrainQueues(drainCtx)

	for _, o := range activeOutputs {
		if closeErr := o.Close(); closeErr != nil {
			log.Printf("output %s close: %v", o.Name(), closeErr)
		}
	}

	log.Println("stopped")
}
