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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

func TestOutputWorkerConfigValidateValid(t *testing.T) {
	cfg := defaultWorkerConfig()
	assert.Empty(t, cfg.Validate())
}

func TestOutputWorkerConfigValidateZeroValues(t *testing.T) {
	cfg := OutputWorkerConfig{}
	assert.NotEmpty(t, cfg.Validate())
}

func TestOutputWorkerConfigValidateNegativeQueueSize(t *testing.T) {
	cfg := defaultWorkerConfig()
	cfg.QueueSize = -1
	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
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
	ctx := context.Background()
	w.Start(ctx)

	w.Enqueue(newTestEvent())

	w.CloseQueue()
	w.WaitDone()

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
	ctx := context.Background()
	w.Start(ctx)

	w.Enqueue(newTestEvent())

	w.CloseQueue()
	w.WaitDone()

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
	ctx := context.Background()
	w.Start(ctx)

	w.Enqueue(newTestEvent())

	w.CloseQueue()
	w.WaitDone()

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
	ctx := context.Background()
	w.Start(ctx)

	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 5; i++ {
		w.Enqueue(newTestEvent())
	}

	assert.Greater(t, w.droppedTotal.Load(), int64(0))

	close(blocked)
	w.CloseQueue()
	w.WaitDone()
}

func TestOutputWorkerCircuitBreakerBlocks(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 1,
		ResetTimeout:     5 * time.Second,
	})

	assert.Equal(t, CircuitClosed, cb.GetState())
	cb.RecordFailure()
	assert.Equal(t, CircuitClosed, cb.GetState())
	cb.RecordFailure()
	assert.Equal(t, CircuitOpen, cb.GetState())

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
	ctx := context.Background()
	w.Start(ctx)

	for i := 0; i < 10; i++ {
		w.Enqueue(newTestEvent())
	}

	w.CloseQueue()
	w.WaitDone()

	assert.Equal(t, int64(2), attempts.Load())
	assert.Equal(t, CircuitOpen, w.circuitBreaker.GetState())
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

func TestOutputWorkerForceStopOnContextCancel(t *testing.T) {
	output := &mockOutput{
		name: "test",
		sendFunc: func(ctx context.Context, _ *domain.Event) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}

	w := NewOutputWorker(output, defaultWorkerConfig(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	w.Start(ctx)

	w.Enqueue(newTestEvent())
	time.Sleep(20 * time.Millisecond)

	cancel()
	w.WaitDone()
}
