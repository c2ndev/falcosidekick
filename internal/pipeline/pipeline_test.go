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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/store"
)

func buildTestPipeline(t *testing.T, outputs []domain.Output) *Pipeline {
	t.Helper()
	enricher, err := NewEnricher(EnricherConfig{TruncateEventThreshold: 4096, TruncateFieldThreshold: 512})
	require.NoError(t, err)
	memStore := store.NewMemoryStore(&store.MemoryConfig{Capacity: 100, GCInterval: 10 * time.Second})
	router := NewRouter(map[string]domain.Priority{})
	dispatcher := NewDispatcher(outputs, defaultWorkerConfig(), nil)

	p, err := NewPipeline(enricher, memStore, router, dispatcher, nil)
	require.NoError(t, err)
	return p
}

func TestProcessEventEnrichesAndDispatches(t *testing.T) {
	var received atomic.Int64
	output := &mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
			received.Add(1)
			return nil
		},
	}

	router := NewRouter(map[string]domain.Priority{"test": domain.PriorityDebug})
	enricher, _ := NewEnricher(EnricherConfig{
		CustomFields:           map[string]string{"env": "test"},
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	memStore := store.NewMemoryStore(&store.MemoryConfig{Capacity: 100, GCInterval: 10 * time.Second})
	dispatcher := NewDispatcher([]domain.Output{output}, defaultWorkerConfig(), nil)

	p, err := NewPipeline(enricher, memStore, router, dispatcher, nil)
	require.NoError(t, err)

	ctx := context.Background()
	p.Start(ctx)

	event := newTestEvent()
	p.ProcessEvent(ctx, event)

	drainCtx, drainCancel := context.WithTimeout(ctx, 2*time.Second)
	defer drainCancel()
	p.DrainQueues(drainCtx)

	assert.Equal(t, int64(1), received.Load())
	assert.NotEmpty(t, event.UUID)
	assert.Equal(t, "test", event.OutputFields["env"])
}

func TestProcessEventStoresAsync(t *testing.T) {
	enricher, _ := NewEnricher(EnricherConfig{TruncateEventThreshold: 4096, TruncateFieldThreshold: 512})
	memStore := store.NewMemoryStore(&store.MemoryConfig{Capacity: 100, GCInterval: 10 * time.Second})
	router := NewRouter(map[string]domain.Priority{})
	dispatcher := NewDispatcher(nil, defaultWorkerConfig(), nil)

	p, err := NewPipeline(enricher, memStore, router, dispatcher, nil)
	require.NoError(t, err)

	ctx := context.Background()
	p.Start(ctx)

	p.ProcessEvent(ctx, newTestEvent())

	drainCtx, drainCancel := context.WithTimeout(ctx, 2*time.Second)
	defer drainCancel()
	p.DrainQueues(drainCtx)

	count, err := memStore.Count(ctx, &domain.Filters{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestProcessEventRoutesByPriority(t *testing.T) {
	var slackCalls, lokiCalls atomic.Int64

	outputs := []domain.Output{
		&mockOutput{name: "slack", sendFunc: func(_ context.Context, _ *domain.Event) error {
			slackCalls.Add(1)
			return nil
		}},
		&mockOutput{name: "loki", sendFunc: func(_ context.Context, _ *domain.Event) error {
			lokiCalls.Add(1)
			return nil
		}},
	}

	router := NewRouter(map[string]domain.Priority{
		"slack": domain.PriorityCritical,
		"loki":  domain.PriorityDebug,
	})
	enricher, _ := NewEnricher(EnricherConfig{TruncateEventThreshold: 4096, TruncateFieldThreshold: 512})
	memStore := store.NewMemoryStore(&store.MemoryConfig{Capacity: 100, GCInterval: 10 * time.Second})
	dispatcher := NewDispatcher(outputs, defaultWorkerConfig(), nil)

	p, err := NewPipeline(enricher, memStore, router, dispatcher, nil)
	require.NoError(t, err)

	ctx := context.Background()
	p.Start(ctx)

	event := newTestEvent()
	event.Priority = domain.PriorityWarning
	p.ProcessEvent(ctx, event)

	drainCtx, drainCancel := context.WithTimeout(ctx, 2*time.Second)
	defer drainCancel()
	p.DrainQueues(drainCtx)

	assert.Equal(t, int64(0), slackCalls.Load(), "warning should not reach critical-only slack")
	assert.Equal(t, int64(1), lokiCalls.Load(), "warning should reach debug-level loki")
}

func TestNewPipelineRejectsNilDependencies(t *testing.T) {
	enricher, _ := NewEnricher(EnricherConfig{TruncateEventThreshold: 4096, TruncateFieldThreshold: 512})
	memStore := store.NewMemoryStore(&store.MemoryConfig{Capacity: 10, GCInterval: 10 * time.Second})
	router := NewRouter(nil)
	dispatcher := NewDispatcher(nil, defaultWorkerConfig(), nil)

	tests := []struct {
		enricher   *Enricher
		store      domain.EventStore
		router     *Router
		dispatcher *Dispatcher
		name       string
	}{
		{name: "nil enricher", enricher: nil, store: memStore, router: router, dispatcher: dispatcher},
		{name: "nil router", enricher: enricher, store: memStore, router: nil, dispatcher: dispatcher},
		{name: "nil dispatcher", enricher: enricher, store: memStore, router: router, dispatcher: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPipeline(tt.enricher, tt.store, tt.router, tt.dispatcher, nil)
			require.Error(t, err)
		})
	}
}

func TestProcessEventWithoutStoreDoesNotPanic(t *testing.T) {
	var received atomic.Int64
	output := &mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
			received.Add(1)
			return nil
		},
	}

	enricher, err := NewEnricher(EnricherConfig{TruncateEventThreshold: 4096, TruncateFieldThreshold: 512})
	require.NoError(t, err)
	p, err := NewPipeline(
		enricher,
		nil,
		NewRouter(map[string]domain.Priority{"test": domain.PriorityDebug}),
		NewDispatcher([]domain.Output{output}, defaultWorkerConfig(), nil),
		nil,
	)
	require.NoError(t, err)

	ctx := context.Background()
	p.Start(ctx)

	p.ProcessEvent(ctx, newTestEvent())

	drainCtx, drainCancel := context.WithTimeout(ctx, 2*time.Second)
	defer drainCancel()
	p.DrainQueues(drainCtx)

	assert.Equal(t, int64(1), received.Load())
}

func TestCollectOutputStatus(t *testing.T) {
	p := buildTestPipeline(t, []domain.Output{
		&mockOutput{name: "slack"},
		&mockOutput{name: "loki"},
	})

	statuses := p.CollectOutputStatus()
	assert.Len(t, statuses, 2)
}

func TestDrainQueuesCompletesWhenEmpty(t *testing.T) {
	p := buildTestPipeline(t, nil)
	ctx := context.Background()
	p.Start(ctx)

	drainCtx, drainCancel := context.WithTimeout(ctx, 1*time.Second)
	defer drainCancel()
	p.DrainQueues(drainCtx)
}
