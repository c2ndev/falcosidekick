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

// Pipeline orchestrates event processing: enrich, store, route, dispatch.
type Pipeline struct {
	enricher   *Enricher
	store      domain.EventStore
	router     *Router
	dispatcher *Dispatcher
	metrics    domain.MetricsCollector
}

// NewPipeline creates a Pipeline from its dependencies.
func NewPipeline(
	enricher *Enricher,
	eventStore domain.EventStore,
	router *Router,
	dispatcher *Dispatcher,
	metrics domain.MetricsCollector,
) (*Pipeline, error) {
	if enricher == nil {
		return nil, fmt.Errorf("pipeline: enricher is required")
	}
	if router == nil {
		return nil, fmt.Errorf("pipeline: router is required")
	}
	if dispatcher == nil {
		return nil, fmt.Errorf("pipeline: dispatcher is required")
	}

	return &Pipeline{
		enricher:   enricher,
		store:      eventStore,
		router:     router,
		dispatcher: dispatcher,
		metrics:    metrics,
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

	targets := p.router.RouteEvent(event)
	p.dispatcher.DispatchEvent(event, targets)

	if p.store != nil {
		if err := p.store.Append(ctx, event); err != nil {
			if p.metrics != nil {
				p.metrics.RecordError(ctx, "eventstore", err)
			}
		}
	}
}

// DrainQueues waits for all output queues to empty and in-flight sends to complete.
func (p *Pipeline) DrainQueues(ctx context.Context) {
	p.dispatcher.DrainQueues(ctx)
}

// CollectOutputStatus returns per-output status for the UI.
func (p *Pipeline) CollectOutputStatus() []OutputStatus {
	return p.dispatcher.CollectStatus()
}
