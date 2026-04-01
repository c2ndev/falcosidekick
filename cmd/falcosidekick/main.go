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

// Package main is the entry point for falcosidekick v3.
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
	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/outputs/all"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/store"
)

func main() {
	cat, err := catalog.New(all.Types())
	if err != nil {
		log.Fatalf("catalog: %v", err)
	}

	memStore := store.NewMemoryStore(store.MemoryConfig{})

	enricher, err := pipeline.NewEnricher(pipeline.EnricherConfig{})
	if err != nil {
		_ = memStore.Close()
		log.Fatalf("enricher: %v", err)
	}

	outputPriorities := make(map[string]domain.Priority)
	var activeOutputs []domain.Output

	webhookURL := os.Getenv("WEBHOOK_ADDRESS")
	if webhookURL != "" {
		cfg := map[string]any{"address": webhookURL}
		output, createErr := cat.Create("webhook", cfg, domain.OutputDeps{})
		if createErr != nil {
			log.Fatalf("webhook output: %v", createErr)
		}
		if initErr := output.Init(context.Background()); initErr != nil {
			log.Fatalf("webhook init: %v", initErr)
		}
		activeOutputs = append(activeOutputs, output)
		outputPriorities["webhook"] = domain.PriorityDebug
	}

	router := pipeline.NewRouter(outputPriorities)
	dispatcher := pipeline.NewDispatcher(activeOutputs, pipeline.OutputWorkerConfig{}, nil)

	pipe, err := pipeline.NewPipeline(pipeline.PipelineConfig{
		Enricher:   enricher,
		Store:      memStore,
		Router:     router,
		Dispatcher: dispatcher,
	})
	if err != nil {
		log.Fatalf("pipeline: %v", err)
	}

	srv, err := api.NewServer(api.ServerConfig{
		Pipeline: pipe,
		Store:    memStore,
	})
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	pipe.Start(ctx)

	go func() {
		log.Printf("falcosidekick v3 listening on %s", "0.0.0.0:2801")
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

	_ = memStore.Close()
	log.Println("stopped")
}
