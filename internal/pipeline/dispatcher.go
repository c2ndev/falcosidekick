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

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
)

// Dispatcher manages outputs and routes events with priority filtering.
type Dispatcher struct {
	outputs []*Output
}

// NewDispatcher creates a Dispatcher for the given outputs.
func NewDispatcher(outputs []*Output) *Dispatcher {
	return &Dispatcher{outputs: outputs}
}

// Start launches all output worker pools.
func (d *Dispatcher) Start(ctx context.Context) {
	for _, out := range d.outputs {
		out.Start(ctx)
	}
}

// DispatchEvent sends an event to all outputs that accept its priority.
func (d *Dispatcher) DispatchEvent(evt *event.Event) {
	for _, out := range d.outputs {
		if acceptsPriority(out.config.MinPriority, evt.Priority) {
			out.Enqueue(evt)
		}
	}
}

// CloseQueues closes all output event channels. Workers finish remaining events then exit.
func (d *Dispatcher) CloseQueues() {
	for _, out := range d.outputs {
		out.CloseQueue()
	}
}

// WaitAll blocks until all output workers have exited.
func (d *Dispatcher) WaitAll() {
	for _, out := range d.outputs {
		out.WaitDone()
	}
}

// CollectStatus returns status for every output.
func (d *Dispatcher) CollectStatus() []OutputStatus {
	statuses := make([]OutputStatus, 0, len(d.outputs))
	for _, out := range d.outputs {
		statuses = append(statuses, out.GetStatus())
	}
	return statuses
}

func acceptsPriority(minPriority, eventPriority event.Priority) bool {
	if minPriority == "" {
		return true
	}
	return eventPriority.GTE(minPriority)
}
