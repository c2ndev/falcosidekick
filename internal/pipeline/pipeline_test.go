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
	enricher, err := NewEnricher(EnricherConfig{})
	require.NoError(t, err)
	memStore := store.NewMemoryStore(store.MemoryConfig{Capacity: 100})
	router := NewRouter(map[string]domain.Priority{})
	dispatcher := NewDispatcher(outputs, OutputWorkerConfig{
		QueueSize: 100,
		Workers:   1,
		Retry:     RetryConfig{MaxAttempts: 1},
	}, nil)

	p, err := NewPipeline(PipelineConfig{
		Enricher:   enricher,
		Store:      memStore,
		Router:     router,
		Dispatcher: dispatcher,
	})
	require.NoError(t, err)
	return p
}

func TestProcessEventEnrichesAndDispatches(t *testing.T) {
	var received atomic.Int64
	output := &mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, event *domain.Event) error {
			received.Add(1)
			return nil
		},
	}

	router := NewRouter(map[string]domain.Priority{
		"test": domain.PriorityDebug,
	})
	enricher, _ := NewEnricher(EnricherConfig{
		CustomFields: map[string]string{"env": "test"},
	})
	memStore := store.NewMemoryStore(store.MemoryConfig{Capacity: 100})
	dispatcher := NewDispatcher([]domain.Output{output}, OutputWorkerConfig{
		QueueSize: 100,
		Workers:   1,
		Retry:     RetryConfig{MaxAttempts: 1},
	}, nil)

	p, err := NewPipeline(PipelineConfig{
		Enricher:   enricher,
		Store:      memStore,
		Router:     router,
		Dispatcher: dispatcher,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)

	event := newTestEvent()
	p.ProcessEvent(ctx, event)

	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, int64(1), received.Load())
	assert.NotEmpty(t, event.UUID)
	assert.Equal(t, "test", event.OutputFields["env"])
}

func TestProcessEventStoresAsync(t *testing.T) {
	enricher, _ := NewEnricher(EnricherConfig{})
	memStore := store.NewMemoryStore(store.MemoryConfig{Capacity: 100})
	router := NewRouter(map[string]domain.Priority{})
	dispatcher := NewDispatcher(nil, OutputWorkerConfig{}, nil)

	p, err := NewPipeline(PipelineConfig{
		Enricher:   enricher,
		Store:      memStore,
		Router:     router,
		Dispatcher: dispatcher,
	})
	require.NoError(t, err)

	ctx := context.Background()
	p.ProcessEvent(ctx, newTestEvent())

	time.Sleep(50 * time.Millisecond)

	count, err := memStore.Count(ctx, &domain.Filters{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestProcessEventRoutesbyPriority(t *testing.T) {
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
	enricher, _ := NewEnricher(EnricherConfig{})
	memStore := store.NewMemoryStore(store.MemoryConfig{Capacity: 100})
	dispatcher := NewDispatcher(outputs, OutputWorkerConfig{
		QueueSize: 100,
		Workers:   1,
		Retry:     RetryConfig{MaxAttempts: 1},
	}, nil)

	p, err := NewPipeline(PipelineConfig{
		Enricher:   enricher,
		Store:      memStore,
		Router:     router,
		Dispatcher: dispatcher,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)

	event := newTestEvent()
	event.Priority = domain.PriorityWarning
	p.ProcessEvent(ctx, event)

	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, int64(0), slackCalls.Load(), "warning should not reach critical-only slack")
	assert.Equal(t, int64(1), lokiCalls.Load(), "warning should reach debug-level loki")
}

func TestNewPipelineRejectsNilDependencies(t *testing.T) {
	enricher, _ := NewEnricher(EnricherConfig{})
	memStore := store.NewMemoryStore(store.MemoryConfig{Capacity: 10})
	router := NewRouter(nil)
	dispatcher := NewDispatcher(nil, OutputWorkerConfig{}, nil)

	tests := []struct {
		cfg  PipelineConfig
		name string
	}{
		{name: "nil enricher", cfg: PipelineConfig{Store: memStore, Router: router, Dispatcher: dispatcher}},
		{name: "nil store", cfg: PipelineConfig{Enricher: enricher, Router: router, Dispatcher: dispatcher}},
		{name: "nil router", cfg: PipelineConfig{Enricher: enricher, Store: memStore, Dispatcher: dispatcher}},
		{name: "nil dispatcher", cfg: PipelineConfig{Enricher: enricher, Store: memStore, Router: router}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPipeline(tt.cfg)
			require.Error(t, err)
		})
	}
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

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	p.DrainQueues(ctx)
}
