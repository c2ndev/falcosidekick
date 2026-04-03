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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

type mockOutput struct {
	sendFunc func(ctx context.Context, event *domain.Event) error
	name     string
}

func (m *mockOutput) Name() string                        { return m.name }
func (m *mockOutput) Init(_ context.Context) error        { return nil }
func (m *mockOutput) HealthCheck(_ context.Context) error { return nil }
func (m *mockOutput) Close() error                        { return nil }
func (m *mockOutput) Send(ctx context.Context, event *domain.Event) error {
	if m.sendFunc != nil {
		return m.sendFunc(ctx, event)
	}
	return nil
}

func defaultWorkerConfig() OutputWorkerConfig {
	return OutputWorkerConfig{
		QueueSize: 100,
		Workers:   1,
		Retry: RetryConfig{
			MaxAttempts:     1,
			InitialInterval: 10 * time.Millisecond,
			MaxInterval:     100 * time.Millisecond,
			Multiplier:      2.0,
		},
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold: 5,
			SuccessThreshold: 2,
			ResetTimeout:     30 * time.Second,
		},
	}
}

func TestDispatcherRoutesToCorrectOutputs(t *testing.T) {
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

	d := NewDispatcher(outputs, defaultWorkerConfig(), nil)
	ctx := context.Background()
	d.Start(ctx)

	d.DispatchEvent(newTestEvent(), []string{"slack"})
	d.DispatchEvent(newTestEvent(), []string{"loki"})
	d.DispatchEvent(newTestEvent(), []string{"slack", "loki"})

	drainCtx, drainCancel := context.WithTimeout(ctx, 2*time.Second)
	defer drainCancel()
	d.DrainQueues(drainCtx)

	assert.Equal(t, int64(2), slackCalls.Load())
	assert.Equal(t, int64(2), lokiCalls.Load())
}

func TestDispatcherIgnoresUnknownTargets(t *testing.T) {
	d := NewDispatcher([]domain.Output{
		&mockOutput{name: "slack"},
	}, defaultWorkerConfig(), nil)

	ctx := context.Background()
	d.Start(ctx)

	d.DispatchEvent(newTestEvent(), []string{"nonexistent"})

	drainCtx, drainCancel := context.WithTimeout(ctx, 1*time.Second)
	defer drainCancel()
	d.DrainQueues(drainCtx)
}

func TestDispatcherCollectStatus(t *testing.T) {
	d := NewDispatcher([]domain.Output{
		&mockOutput{name: "slack"},
		&mockOutput{name: "loki"},
	}, defaultWorkerConfig(), nil)

	statuses := d.CollectStatus()
	assert.Len(t, statuses, 2)

	names := make(map[string]bool)
	for _, s := range statuses {
		names[s.Name] = true
	}
	assert.True(t, names["slack"])
	assert.True(t, names["loki"])
}

func TestDispatcherDrainQueues(t *testing.T) {
	var mu sync.Mutex
	var received []string

	output := &mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, event *domain.Event) error {
			mu.Lock()
			received = append(received, event.Rule)
			mu.Unlock()
			return nil
		},
	}

	d := NewDispatcher([]domain.Output{output}, defaultWorkerConfig(), nil)
	ctx := context.Background()
	d.Start(ctx)

	for i := 0; i < 10; i++ {
		e := newTestEvent()
		e.Rule = fmt.Sprintf("rule-%d", i)
		d.DispatchEvent(e, []string{"test"})
	}

	drainCtx, drainCancel := context.WithTimeout(ctx, 2*time.Second)
	defer drainCancel()
	d.DrainQueues(drainCtx)

	mu.Lock()
	assert.Len(t, received, 10)
	mu.Unlock()
}

func TestDispatcherConcurrentDispatch(t *testing.T) {
	var count atomic.Int64
	output := &mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
			count.Add(1)
			return nil
		},
	}

	cfg := defaultWorkerConfig()
	cfg.Workers = 4

	d := NewDispatcher([]domain.Output{output}, cfg, nil)
	ctx := context.Background()
	d.Start(ctx)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.DispatchEvent(newTestEvent(), []string{"test"})
		}()
	}
	wg.Wait()

	drainCtx, drainCancel := context.WithTimeout(ctx, 2*time.Second)
	defer drainCancel()
	d.DrainQueues(drainCtx)

	require.Equal(t, int64(100), count.Load())
}

func TestDrainQueuesWaitsForActiveSend(t *testing.T) {
	sendStarted := make(chan struct{})
	sendBlock := make(chan struct{})
	var sendCompleted atomic.Bool

	output := &mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
			close(sendStarted)
			<-sendBlock
			sendCompleted.Store(true)
			return nil
		},
	}

	d := NewDispatcher([]domain.Output{output}, defaultWorkerConfig(), nil)
	ctx := context.Background()
	d.Start(ctx)

	d.DispatchEvent(newTestEvent(), []string{"test"})

	<-sendStarted

	drainDone := make(chan struct{})
	go func() {
		drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer drainCancel()
		d.DrainQueues(drainCtx)
		close(drainDone)
	}()

	time.Sleep(100 * time.Millisecond)
	select {
	case <-drainDone:
		t.Fatal("DrainQueues returned while Send was still active")
	default:
	}

	close(sendBlock)

	select {
	case <-drainDone:
		assert.True(t, sendCompleted.Load(), "Send must complete before DrainQueues returns")
	case <-time.After(5 * time.Second):
		t.Fatal("DrainQueues did not return after Send completed")
	}
}
