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

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

type mockOutput struct {
	sendFunc func(ctx context.Context, evt *event.Event) error
	name     string
}

func (m *mockOutput) Name() string                        { return m.name }
func (m *mockOutput) Init(_ context.Context) error        { return nil }
func (m *mockOutput) HealthCheck(_ context.Context) error { return nil }
func (m *mockOutput) Close() error                        { return nil }
func (m *mockOutput) Send(ctx context.Context, evt *event.Event) error {
	if m.sendFunc != nil {
		return m.sendFunc(ctx, evt)
	}
	return nil
}

func defaultPipelineDefaults() *output.Config {
	return &output.Config{
		QueueSize: 100,
		Workers:   1,
		Retry: &output.RetryConfig{
			MaxAttempts:     1,
			InitialInterval: 10 * time.Millisecond,
			MaxInterval:     100 * time.Millisecond,
			Multiplier:      2.0,
		},
		CircuitBreaker: &output.CircuitBreakerConfig{
			FailureThreshold: 5,
			SuccessThreshold: 2,
			ResetTimeout:     30 * time.Second,
		},
	}
}

func TestDispatcherRoutesToCorrectOutputs(t *testing.T) {
	var slackCalls, lokiCalls atomic.Int64

	slackCfg := defaultPipelineDefaults()
	slackCfg.MinPriority = event.PriorityCritical
	slackOut := NewOutput(&mockOutput{name: "slack", sendFunc: func(_ context.Context, _ *event.Event) error {
		slackCalls.Add(1)
		return nil
	}}, slackCfg, nil)

	lokiCfg := defaultPipelineDefaults()
	lokiCfg.MinPriority = event.PriorityDebug
	lokiOut := NewOutput(&mockOutput{name: "loki", sendFunc: func(_ context.Context, _ *event.Event) error {
		lokiCalls.Add(1)
		return nil
	}}, lokiCfg, nil)

	d := NewDispatcher([]*Output{slackOut, lokiOut})
	ctx := context.Background()
	d.Start(ctx)

	evt := newTestEvent()
	evt.Priority = event.PriorityWarning
	d.DispatchEvent(evt)

	d.CloseQueues()
	d.WaitAll()

	assert.Equal(t, int64(0), slackCalls.Load(), "warning evt must not reach critical-only slack")
	assert.Equal(t, int64(1), lokiCalls.Load(), "warning evt must reach debug-level loki")
}

func TestDispatcherCollectStatus(t *testing.T) {
	d := NewDispatcher([]*Output{
		NewOutput(&mockOutput{name: "slack"}, defaultPipelineDefaults(), nil),
		NewOutput(&mockOutput{name: "loki"}, defaultPipelineDefaults(), nil),
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
		sendFunc: func(_ context.Context, evt *event.Event) error {
			mu.Lock()
			received = append(received, evt.Rule)
			mu.Unlock()
			return nil
		},
	}, defaultPipelineDefaults(), nil)

	d := NewDispatcher([]*Output{out})
	ctx := context.Background()
	d.Start(ctx)

	for i := 0; i < 10; i++ {
		e := newTestEvent()
		e.Rule = fmt.Sprintf("rule-%d", i)
		d.DispatchEvent(e)
	}

	d.CloseQueues()
	d.WaitAll()

	mu.Lock()
	assert.Len(t, received, 10)
	mu.Unlock()
}

func TestDispatcherConcurrentDispatch(t *testing.T) {
	var count atomic.Int64

	cfg := defaultPipelineDefaults()
	cfg.Workers = 4

	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *event.Event) error {
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

	d.CloseQueues()
	d.WaitAll()

	require.Equal(t, int64(100), count.Load())
}

func TestDrainQueuesWaitsForActiveSend(t *testing.T) {
	sendStarted := make(chan struct{})
	sendBlock := make(chan struct{})
	var sendCompleted atomic.Bool

	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *event.Event) error {
			close(sendStarted)
			<-sendBlock
			sendCompleted.Store(true)
			return nil
		},
	}, defaultPipelineDefaults(), nil)

	d := NewDispatcher([]*Output{out})
	ctx := context.Background()
	d.Start(ctx)

	d.DispatchEvent(newTestEvent())
	<-sendStarted

	drainDone := make(chan struct{})
	go func() {
		d.CloseQueues()
		d.WaitAll()
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

func TestCloseQueuesAndCancelStopsSlowWorker(t *testing.T) {
	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(ctx context.Context, _ *event.Event) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}, defaultPipelineDefaults(), nil)

	d := NewDispatcher([]*Output{out})
	workerCtx, workerCancel := context.WithCancel(context.Background())
	d.Start(workerCtx)

	d.DispatchEvent(newTestEvent())
	time.Sleep(20 * time.Millisecond)

	start := time.Now()
	d.CloseQueues()
	workerCancel()
	d.WaitAll()
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 500*time.Millisecond, "cancel + WaitAll must complete quickly when workers respect ctx")
}

func TestTwoContextShutdown(t *testing.T) {
	sendStarted := make(chan struct{})
	var sendCanceled atomic.Bool

	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(ctx context.Context, _ *event.Event) error {
			close(sendStarted)
			<-ctx.Done()
			sendCanceled.Store(true)
			return ctx.Err()
		},
	}, defaultPipelineDefaults(), nil)

	d := NewDispatcher([]*Output{out})

	workerCtx, workerCancel := context.WithCancel(context.Background())
	d.Start(workerCtx)

	d.DispatchEvent(newTestEvent())
	<-sendStarted

	// Close queues - worker is blocked in Send, won't drain
	d.CloseQueues()

	// Worker still alive (blocked in Send)
	time.Sleep(50 * time.Millisecond)
	assert.False(t, sendCanceled.Load(), "worker should still be in Send after close queues")

	// Cancel context -> worker sees ctx.Done -> exits
	workerCancel()

	// Wait for worker to observe cancellation
	d.WaitAll()
	assert.True(t, sendCanceled.Load(), "worker must exit after context cancel")
}
