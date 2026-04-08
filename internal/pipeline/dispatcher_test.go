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

func defaultOutputConfig() *OutputConfig {
	return &OutputConfig{
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

	slackCfg := defaultOutputConfig()
	slackCfg.MinPriority = domain.PriorityCritical
	slackOut := NewOutput(&mockOutput{name: "slack", sendFunc: func(_ context.Context, _ *domain.Event) error {
		slackCalls.Add(1)
		return nil
	}}, slackCfg, nil)

	lokiCfg := defaultOutputConfig()
	lokiCfg.MinPriority = domain.PriorityDebug
	lokiOut := NewOutput(&mockOutput{name: "loki", sendFunc: func(_ context.Context, _ *domain.Event) error {
		lokiCalls.Add(1)
		return nil
	}}, lokiCfg, nil)

	d := NewDispatcher([]*Output{slackOut, lokiOut})
	ctx := context.Background()
	d.Start(ctx)

	event := newTestEvent()
	event.Priority = domain.PriorityWarning
	d.DispatchEvent(event)

	drainCtx, drainCancel := context.WithTimeout(ctx, 2*time.Second)
	defer drainCancel()
	d.DrainQueues(drainCtx)

	assert.Equal(t, int64(0), slackCalls.Load(), "warning event must not reach critical-only slack")
	assert.Equal(t, int64(1), lokiCalls.Load(), "warning event must reach debug-level loki")
}

func TestDispatcherCollectStatus(t *testing.T) {
	d := NewDispatcher([]*Output{
		NewOutput(&mockOutput{name: "slack"}, defaultOutputConfig(), nil),
		NewOutput(&mockOutput{name: "loki"}, defaultOutputConfig(), nil),
	})

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

	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, event *domain.Event) error {
			mu.Lock()
			received = append(received, event.Rule)
			mu.Unlock()
			return nil
		},
	}, defaultOutputConfig(), nil)

	d := NewDispatcher([]*Output{out})
	ctx := context.Background()
	d.Start(ctx)

	for i := 0; i < 10; i++ {
		e := newTestEvent()
		e.Rule = fmt.Sprintf("rule-%d", i)
		d.DispatchEvent(e)
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

	cfg := defaultOutputConfig()
	cfg.Workers = 4

	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
			count.Add(1)
			return nil
		},
	}, cfg, nil)

	d := NewDispatcher([]*Output{out})
	ctx := context.Background()
	d.Start(ctx)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.DispatchEvent(newTestEvent())
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

	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
			close(sendStarted)
			<-sendBlock
			sendCompleted.Store(true)
			return nil
		},
	}, defaultOutputConfig(), nil)

	d := NewDispatcher([]*Output{out})
	ctx := context.Background()
	d.Start(ctx)

	d.DispatchEvent(newTestEvent())
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

func TestDrainQueuesReturnsOnTimeout(t *testing.T) {
	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
			time.Sleep(10 * time.Second)
			return nil
		},
	}, defaultOutputConfig(), nil)

	d := NewDispatcher([]*Output{out})
	ctx := context.Background()
	d.Start(ctx)

	d.DispatchEvent(newTestEvent())
	time.Sleep(20 * time.Millisecond)

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer drainCancel()

	start := time.Now()
	d.DrainQueues(drainCtx)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 500*time.Millisecond, "DrainQueues must return when timeout fires, not wait for slow send")
}

func TestTwoContextShutdown(t *testing.T) {
	sendStarted := make(chan struct{})
	var sendCanceled atomic.Bool

	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(ctx context.Context, _ *domain.Event) error {
			close(sendStarted)
			<-ctx.Done()
			sendCanceled.Store(true)
			return ctx.Err()
		},
	}, defaultOutputConfig(), nil)

	d := NewDispatcher([]*Output{out})

	// Two-context design: drainCtx is parent, workerCtx is child
	drainCtx, drainCancel := context.WithCancel(context.Background())
	defer drainCancel()

	workerCtx, workerCancel := context.WithCancel(drainCtx)
	defer workerCancel()

	d.Start(workerCtx)

	d.DispatchEvent(newTestEvent())
	<-sendStarted

	// Drain with short timeout - worker is blocked in Send
	drainTimeout, drainTimeoutCancel := context.WithTimeout(drainCtx, 100*time.Millisecond)
	defer drainTimeoutCancel()
	d.DrainQueues(drainTimeout)

	// DrainQueues returned (timeout), but worker is still alive (blocked in Send)
	assert.False(t, sendCanceled.Load(), "worker should still be in Send after drain timeout")

	// Cancel drainCtx -> cancels workerCtx (child) -> worker sees ctx.Done -> exits
	drainCancel()

	// Wait for worker to observe the cancellation
	time.Sleep(50 * time.Millisecond)
	assert.True(t, sendCanceled.Load(), "worker must exit after workerCtx is canceled via parent drainCtx")
}
