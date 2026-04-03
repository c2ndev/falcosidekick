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

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

// Dispatcher routes events to per-output worker pools.
type Dispatcher struct {
	workers map[string]*OutputWorker
}

// NewDispatcher creates a Dispatcher with workers for each output.
func NewDispatcher(outputs []domain.Output, defaultCfg OutputWorkerConfig, metrics domain.MetricsCollector) *Dispatcher {
	workers := make(map[string]*OutputWorker, len(outputs))
	for _, output := range outputs {
		workers[output.Name()] = NewOutputWorker(output, defaultCfg, metrics)
	}
	return &Dispatcher{workers: workers}
}

// Start launches all output worker pools.
func (d *Dispatcher) Start(ctx context.Context) {
	for _, w := range d.workers {
		w.Start(ctx)
	}
}

// DispatchEvent sends an event to the named output workers.
func (d *Dispatcher) DispatchEvent(event *domain.Event, targets []string) {
	for _, name := range targets {
		if w, ok := d.workers[name]; ok {
			w.Enqueue(event)
		}
	}
}

// DrainQueues closes all output queues and waits for workers to finish
// processing remaining events. Respects ctx for timeout.
func (d *Dispatcher) DrainQueues(ctx context.Context) {
	for _, w := range d.workers {
		w.CloseQueue()
	}

	done := make(chan struct{})
	go func() {
		for _, w := range d.workers {
			w.WaitDone()
		}
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

// CollectStatus returns status for every output worker.
func (d *Dispatcher) CollectStatus() []OutputStatus {
	statuses := make([]OutputStatus, 0, len(d.workers))
	for _, w := range d.workers {
		statuses = append(statuses, w.GetStatus())
	}
	return statuses
}
