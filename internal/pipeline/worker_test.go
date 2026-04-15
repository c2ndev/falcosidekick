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

type mockBatchOutput struct {
	sendBatchFunc func(ctx context.Context, events []*event.Event) error
	mockOutput
}

func (m *mockBatchOutput) SendBatch(ctx context.Context, events []*event.Event) error {
	if m.sendBatchFunc != nil {
		return m.sendBatchFunc(ctx, events)
	}
	return nil
}

func batchPipelineDefaults(batchSize int, flushInterval time.Duration) *output.Config {
	cfg := defaultPipelineDefaults()
	cfg.Batching = &output.BatchingConfig{
		Enabled:       true,
		BatchSize:     batchSize,
		FlushInterval: flushInterval,
	}
	return cfg
}

func TestBatchWorkerFlushOnSize(t *testing.T) {
	var mu sync.Mutex
	var batches []int

	cfg := batchPipelineDefaults(5, 10*time.Second)
	out := NewOutput(&mockBatchOutput{
		mockOutput: mockOutput{name: "batch-test"},
		sendBatchFunc: func(_ context.Context, events []*event.Event) error {
			mu.Lock()
			batches = append(batches, len(events))
			mu.Unlock()
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 10; i++ {
		out.Enqueue(newTestEvent())
	}

	out.CloseQueue()
	out.WaitDone()

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, batches)
	total := 0
	for _, b := range batches {
		assert.LessOrEqual(t, b, 5, "batch must not exceed configured size")
		total += b
	}
	assert.Equal(t, 10, total, "all events must be delivered")
}

func TestBatchWorkerFlushOnInterval(t *testing.T) {
	var mu sync.Mutex
	var batches []int

	cfg := batchPipelineDefaults(100, 50*time.Millisecond)
	out := NewOutput(&mockBatchOutput{
		mockOutput: mockOutput{name: "batch-test"},
		sendBatchFunc: func(_ context.Context, events []*event.Event) error {
			mu.Lock()
			batches = append(batches, len(events))
			mu.Unlock()
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 3; i++ {
		out.Enqueue(newTestEvent())
	}

	time.Sleep(150 * time.Millisecond)

	out.CloseQueue()
	out.WaitDone()

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, batches, "timer must trigger flush before queue close")
	total := 0
	for _, b := range batches {
		total += b
	}
	assert.Equal(t, 3, total)
}

func TestBatchWorkerFlushOnClose(t *testing.T) {
	var mu sync.Mutex
	var batches []int

	cfg := batchPipelineDefaults(100, 10*time.Second)
	out := NewOutput(&mockBatchOutput{
		mockOutput: mockOutput{name: "batch-test"},
		sendBatchFunc: func(_ context.Context, events []*event.Event) error {
			mu.Lock()
			batches = append(batches, len(events))
			mu.Unlock()
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 3; i++ {
		out.Enqueue(newTestEvent())
	}

	out.CloseQueue()
	out.WaitDone()

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, batches, "remaining events must be flushed on queue close")
	total := 0
	for _, b := range batches {
		total += b
	}
	assert.Equal(t, 3, total)
}

func TestBatchWorkerContextCancel(t *testing.T) {
	var mu sync.Mutex
	var batches []int

	cfg := batchPipelineDefaults(100, 10*time.Second)
	out := NewOutput(&mockBatchOutput{
		mockOutput: mockOutput{name: "batch-test"},
		sendBatchFunc: func(_ context.Context, events []*event.Event) error {
			mu.Lock()
			batches = append(batches, len(events))
			mu.Unlock()
			return nil
		},
	}, cfg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	out.Start(ctx)

	for i := 0; i < 3; i++ {
		out.Enqueue(newTestEvent())
	}
	time.Sleep(20 * time.Millisecond)

	cancel()
	out.WaitDone()

	mu.Lock()
	defer mu.Unlock()
	total := 0
	for _, b := range batches {
		total += b
	}
	assert.Equal(t, 3, total, "buffered events must be flushed on context cancel")
}

func TestBatchWorkerDisabledFallsBackToSingle(t *testing.T) {
	var singleCalls atomic.Int64
	var batchCalls atomic.Int64

	cfg := defaultPipelineDefaults()
	cfg.Batching = &output.BatchingConfig{Enabled: false, BatchSize: 5, FlushInterval: time.Second}

	out := NewOutput(&mockBatchOutput{
		mockOutput: mockOutput{
			name: "batch-test",
			sendFunc: func(_ context.Context, _ *event.Event) error {
				singleCalls.Add(1)
				return nil
			},
		},
		sendBatchFunc: func(_ context.Context, _ []*event.Event) error {
			batchCalls.Add(1)
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 5; i++ {
		out.Enqueue(newTestEvent())
	}

	out.CloseQueue()
	out.WaitDone()

	assert.Equal(t, int64(5), singleCalls.Load(), "disabled batching must use single Send")
	assert.Equal(t, int64(0), batchCalls.Load(), "SendBatch must not be called when disabled")
}

func TestBatchWorkerNonBatchDriver(t *testing.T) {
	var singleCalls atomic.Int64

	cfg := defaultPipelineDefaults()
	cfg.Batching = &output.BatchingConfig{Enabled: true, BatchSize: 5, FlushInterval: time.Second}

	out := NewOutput(&mockOutput{
		name: "non-batch",
		sendFunc: func(_ context.Context, _ *event.Event) error {
			singleCalls.Add(1)
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 5; i++ {
		out.Enqueue(newTestEvent())
	}

	out.CloseQueue()
	out.WaitDone()

	assert.Equal(t, int64(5), singleCalls.Load(), "non-BatchSender driver must use single Send")
}

func TestBatchWorkerRetryOnFailure(t *testing.T) {
	var attempts atomic.Int64

	cfg := batchPipelineDefaults(5, 10*time.Second)
	cfg.Retry = &output.RetryConfig{
		MaxAttempts:     3,
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     50 * time.Millisecond,
		Multiplier:      2.0,
	}

	out := NewOutput(&mockBatchOutput{
		mockOutput: mockOutput{name: "batch-test"},
		sendBatchFunc: func(_ context.Context, _ []*event.Event) error {
			n := attempts.Add(1)
			if n <= 2 {
				return fmt.Errorf("transient error")
			}
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 5; i++ {
		out.Enqueue(newTestEvent())
	}

	out.CloseQueue()
	out.WaitDone()

	assert.Equal(t, int64(3), attempts.Load(), "batch must be retried")
	assert.Equal(t, int64(5), out.sentTotal.Load(), "all events in batch counted on success")
}

func TestWorkerSendsEvent(t *testing.T) {
	var received atomic.Int64
	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *event.Event) error {
			received.Add(1)
			return nil
		},
	}, defaultPipelineDefaults(), nil)

	ctx := context.Background()
	out.Start(ctx)
	out.Enqueue(newTestEvent())
	out.CloseQueue()
	out.WaitDone()

	assert.Equal(t, int64(1), received.Load())
	assert.Equal(t, int64(1), out.sentTotal.Load())
}

func TestWorkerRetriesOnFailure(t *testing.T) {
	var attempts atomic.Int64
	cfg := defaultPipelineDefaults()
	cfg.Retry = &output.RetryConfig{
		MaxAttempts:     4,
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     50 * time.Millisecond,
		Multiplier:      2.0,
	}

	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *event.Event) error {
			n := attempts.Add(1)
			if n <= 2 {
				return fmt.Errorf("transient error")
			}
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)
	out.Enqueue(newTestEvent())
	out.CloseQueue()
	out.WaitDone()

	assert.Equal(t, int64(3), attempts.Load())
	assert.Equal(t, int64(1), out.sentTotal.Load())
}

func TestWorkerFailsAfterMaxRetries(t *testing.T) {
	cfg := defaultPipelineDefaults()
	cfg.Retry = &output.RetryConfig{
		MaxAttempts:     2,
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     10 * time.Millisecond,
		Multiplier:      1.0,
	}

	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *event.Event) error {
			return fmt.Errorf("persistent error")
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)
	out.Enqueue(newTestEvent())
	out.CloseQueue()
	out.WaitDone()

	assert.Equal(t, int64(0), out.sentTotal.Load())
	assert.Equal(t, int64(1), out.failedTotal.Load())
	assert.Contains(t, out.lastError.Load().(string), "persistent error")
}

func TestWorkerCircuitBreakerBlocks(t *testing.T) {
	var attempts atomic.Int64
	cfg := defaultPipelineDefaults()
	cfg.Workers = 1
	cfg.QueueSize = 100
	cfg.Retry = &output.RetryConfig{
		MaxAttempts:     1,
		InitialInterval: 1 * time.Millisecond,
		MaxInterval:     1 * time.Millisecond,
		Multiplier:      1.0,
	}
	cfg.CircuitBreaker = &output.CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 1,
		ResetTimeout:     5 * time.Second,
	}

	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *event.Event) error {
			attempts.Add(1)
			return fmt.Errorf("fail")
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 10; i++ {
		out.Enqueue(newTestEvent())
	}

	out.CloseQueue()
	out.WaitDone()

	assert.Equal(t, int64(2), attempts.Load())
	assert.Equal(t, CircuitOpen, out.circuitBreaker.GetState())
}

func TestWorkerForceStopOnContextCancel(t *testing.T) {
	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(ctx context.Context, _ *event.Event) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}, defaultPipelineDefaults(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	out.Start(ctx)

	out.Enqueue(newTestEvent())
	time.Sleep(20 * time.Millisecond)

	cancel()
	out.WaitDone()
}
