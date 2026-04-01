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
		Retry:     RetryConfig{MaxAttempts: 1},
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold: 5,
			SuccessThreshold: 2,
			ResetTimeout:     30 * time.Second,
		},
	}
}

func TestOutputWorkerSendsEvent(t *testing.T) {
	var received atomic.Int64
	output := &mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
			received.Add(1)
			return nil
		},
	}

	w := NewOutputWorker(output, defaultWorkerConfig(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	w.Enqueue(newTestEvent())
	time.Sleep(50 * time.Millisecond)

	assert.Equal(t, int64(1), received.Load())
	assert.Equal(t, int64(1), w.sentTotal.Load())
	assert.Equal(t, int64(0), w.failedTotal.Load())
}

func TestOutputWorkerRetriesOnFailure(t *testing.T) {
	var attempts atomic.Int64
	output := &mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
			n := attempts.Add(1)
			if n <= 2 {
				return fmt.Errorf("transient error")
			}
			return nil
		},
	}

	cfg := defaultWorkerConfig()
	cfg.Retry = RetryConfig{
		MaxAttempts:     4,
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     50 * time.Millisecond,
		Multiplier:      2.0,
	}

	w := NewOutputWorker(output, cfg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	w.Enqueue(newTestEvent())
	time.Sleep(300 * time.Millisecond)

	// Fails on attempt 0 and 1, succeeds on attempt 2. Total 3 attempts out of max 4.
	assert.Equal(t, int64(3), attempts.Load())
	assert.Equal(t, int64(1), w.sentTotal.Load())
	assert.Equal(t, int64(0), w.failedTotal.Load())
}

func TestOutputWorkerFailsAfterMaxRetries(t *testing.T) {
	output := &mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
			return fmt.Errorf("persistent error")
		},
	}

	cfg := defaultWorkerConfig()
	cfg.Retry = RetryConfig{
		MaxAttempts:     2,
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     10 * time.Millisecond,
		Multiplier:      1.0,
	}

	w := NewOutputWorker(output, cfg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	w.Enqueue(newTestEvent())
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, int64(0), w.sentTotal.Load())
	assert.Equal(t, int64(1), w.failedTotal.Load())
	assert.Contains(t, w.lastError.Load().(string), "persistent error")
}

func TestOutputWorkerDropsWhenQueueFull(t *testing.T) {
	blocked := make(chan struct{})
	output := &mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
			<-blocked
			return nil
		},
	}

	cfg := defaultWorkerConfig()
	cfg.QueueSize = 2
	cfg.Workers = 1

	w := NewOutputWorker(output, cfg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 5; i++ {
		w.Enqueue(newTestEvent())
	}

	assert.Greater(t, w.droppedTotal.Load(), int64(0))
	close(blocked)
}

func TestOutputWorkerCircuitBreakerBlocks(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 1,
		ResetTimeout:     5 * time.Second,
	})

	// Verify circuit breaker directly: 2 failures -> open
	assert.Equal(t, CircuitClosed, cb.GetState())
	cb.RecordFailure()
	assert.Equal(t, CircuitClosed, cb.GetState())
	cb.RecordFailure()
	assert.Equal(t, CircuitOpen, cb.GetState())

	// Verify worker uses circuit breaker: failing output opens circuit, subsequent events skip Send
	var attempts atomic.Int64
	output := &mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
			attempts.Add(1)
			return fmt.Errorf("fail")
		},
	}

	cfg := defaultWorkerConfig()
	cfg.Workers = 1
	cfg.QueueSize = 100
	cfg.Retry = RetryConfig{
		MaxAttempts:     1,
		InitialInterval: 1 * time.Millisecond,
		MaxInterval:     1 * time.Millisecond,
		Multiplier:      1.0,
	}
	cfg.CircuitBreaker = CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 1,
		ResetTimeout:     5 * time.Second,
	}

	w := NewOutputWorker(output, cfg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)

	for i := 0; i < 10; i++ {
		w.Enqueue(newTestEvent())
	}

	time.Sleep(300 * time.Millisecond)

	// 2 attempts hit the output, then circuit opens blocking the rest
	assert.Equal(t, int64(2), attempts.Load())
	assert.Equal(t, CircuitOpen, w.circuitBreaker.GetState())
}

func TestOutputWorkerDefaults(t *testing.T) {
	output := &mockOutput{name: "test"}
	w := NewOutputWorker(output, OutputWorkerConfig{}, nil)

	assert.Equal(t, 1000, w.queueCapacity)
	assert.Equal(t, 2, w.workerCount)
}

func TestOutputWorkerGetStatus(t *testing.T) {
	output := &mockOutput{name: "slack"}
	w := NewOutputWorker(output, defaultWorkerConfig(), nil)

	status := w.GetStatus()
	assert.Equal(t, "slack", status.Name)
	assert.Equal(t, 0, status.QueueDepth)
	assert.Equal(t, 100, status.QueueCapacity)
	assert.Equal(t, "closed", status.CircuitState)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	d.DispatchEvent(newTestEvent(), []string{"slack"})
	d.DispatchEvent(newTestEvent(), []string{"loki"})
	d.DispatchEvent(newTestEvent(), []string{"slack", "loki"})

	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, int64(2), slackCalls.Load())
	assert.Equal(t, int64(2), lokiCalls.Load())
}

func TestDispatcherIgnoresUnknownTargets(t *testing.T) {
	d := NewDispatcher([]domain.Output{
		&mockOutput{name: "slack"},
	}, defaultWorkerConfig(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	d.DispatchEvent(newTestEvent(), []string{"nonexistent"})
	time.Sleep(50 * time.Millisecond)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	for i := 0; i < 10; i++ {
		e := newTestEvent()
		e.Rule = fmt.Sprintf("rule-%d", i)
		d.DispatchEvent(e, []string{"test"})
	}

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 2*time.Second)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer drainCancel()
	d.DrainQueues(drainCtx)

	require.Equal(t, int64(100), count.Load())
}
