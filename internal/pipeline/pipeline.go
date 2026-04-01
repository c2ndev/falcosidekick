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

package pipeline

import (
	"context"
	"fmt"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

// PipelineConfig holds pipeline dependencies.
type PipelineConfig struct {
	Enricher   *Enricher
	Store      domain.EventStore
	Router     *Router
	Dispatcher *Dispatcher
	Metrics    domain.MetricsCollector
}

// Pipeline orchestrates event processing: enrich, store, route, dispatch.
type Pipeline struct {
	enricher   *Enricher
	store      domain.EventStore
	router     *Router
	dispatcher *Dispatcher
	metrics    domain.MetricsCollector
}

// NewPipeline creates a Pipeline from its dependencies.
func NewPipeline(cfg PipelineConfig) (*Pipeline, error) {
	if cfg.Enricher == nil {
		return nil, fmt.Errorf("pipeline: enricher is required")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("pipeline: store is required")
	}
	if cfg.Router == nil {
		return nil, fmt.Errorf("pipeline: router is required")
	}
	if cfg.Dispatcher == nil {
		return nil, fmt.Errorf("pipeline: dispatcher is required")
	}
	return &Pipeline{
		enricher:   cfg.Enricher,
		store:      cfg.Store,
		router:     cfg.Router,
		dispatcher: cfg.Dispatcher,
		metrics:    cfg.Metrics,
	}, nil
}

// Start launches the dispatcher worker pools.
func (p *Pipeline) Start(ctx context.Context) {
	p.dispatcher.Start(ctx)
}

// ProcessEvent enriches, stores, routes, and dispatches an event.
func (p *Pipeline) ProcessEvent(ctx context.Context, event *domain.Event) {
	if err := p.enricher.Enrich(event); err != nil {
		if p.metrics != nil {
			p.metrics.RecordError(ctx, "enricher", err)
		}
		return
	}

	if p.metrics != nil {
		p.metrics.RecordEvent(ctx, event.Rule, event.Priority, event.Source)
	}

	go func() {
		if err := p.store.Append(ctx, event); err != nil {
			if p.metrics != nil {
				p.metrics.RecordError(ctx, "eventstore", err)
			}
		}
	}()

	targets := p.router.RouteEvent(event)
	p.dispatcher.DispatchEvent(event, targets)
}

// DrainQueues waits for all output queues to empty.
func (p *Pipeline) DrainQueues(ctx context.Context) {
	p.dispatcher.DrainQueues(ctx)
}

// CollectOutputStatus returns per-output status for the UI.
func (p *Pipeline) CollectOutputStatus() []OutputStatus {
	return p.dispatcher.CollectStatus()
}
