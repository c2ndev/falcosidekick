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

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
)

// Pipeline orchestrates event processing: enrich and dispatch.
// It owns the worker lifecycle: Start creates an internal context,
// Shutdown drains and force-stops workers within the caller's deadline.
type Pipeline struct {
	enricher     *Enricher
	dispatcher   *Dispatcher
	metrics      core.MetricsCollector
	workerCancel context.CancelFunc
}

// NewPipeline creates a Pipeline from its dependencies.
func NewPipeline(
	enricher *Enricher,
	dispatcher *Dispatcher,
	metrics core.MetricsCollector,
) (*Pipeline, error) {
	if enricher == nil {
		return nil, fmt.Errorf("pipeline: enricher is required")
	}
	if dispatcher == nil {
		return nil, fmt.Errorf("pipeline: dispatcher is required")
	}

	return &Pipeline{
		enricher:   enricher,
		dispatcher: dispatcher,
		metrics:    metrics,
	}, nil
}

// Start launches the dispatcher worker pools with an internally owned context.
func (p *Pipeline) Start() {
	ctx, cancel := context.WithCancel(context.Background()) //nolint:gosec // cancel is stored in workerCancel and called in Shutdown
	p.workerCancel = cancel
	p.dispatcher.Start(ctx)
}

// Shutdown performs an orderly teardown within the caller's deadline:
//  1. Closes all output queues (workers process remaining events)
//  2. Waits for workers to exit (bounded by ctx)
//  3. If ctx expires, cancels the worker context to force-stop any blocked workers
//  4. Waits for forced workers to exit (immediate after cancel)
//
// After Shutdown returns, all workers are guaranteed to have exited.
func (p *Pipeline) Shutdown(ctx context.Context) {
	p.dispatcher.CloseQueues()

	done := make(chan struct{})
	go func() {
		p.dispatcher.WaitAll()
		close(done)
	}()

	select {
	case <-done:
		// All workers drained and exited gracefully.
	case <-ctx.Done():
		// Timeout: force-cancel worker context.
		if p.workerCancel != nil {
			p.workerCancel()
		}
		// Workers exit immediately on context cancel. Wait for them.
		<-done
	}
}

// ProcessEvent enriches and dispatches an event to all active outputs.
func (p *Pipeline) ProcessEvent(ctx context.Context, evt *event.Event) {
	if err := p.enricher.Enrich(evt); err != nil {
		if p.metrics != nil {
			p.metrics.RecordError(ctx, "enricher", err)
		}
		return
	}

	if p.metrics != nil {
		p.metrics.RecordEvent(ctx, evt.Rule, evt.Priority, evt.Source)
	}

	p.dispatcher.DispatchEvent(evt)
}

// CollectOutputStatus returns per-output status for the UI.
func (p *Pipeline) CollectOutputStatus() []OutputStatus {
	return p.dispatcher.CollectStatus()
}
