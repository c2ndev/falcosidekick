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

func TestOutputConfigValidateValid(t *testing.T) {
	cfg := defaultOutputConfig()
	assert.Empty(t, cfg.Validate())
}

func TestOutputConfigValidateZeroValues(t *testing.T) {
	cfg := OutputConfig{}
	assert.NotEmpty(t, cfg.Validate())
}

func TestOutputConfigValidateNegativeQueueSize(t *testing.T) {
	cfg := defaultOutputConfig()
	cfg.QueueSize = -1
	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
}

func TestOutputSendsEvent(t *testing.T) {
	var received atomic.Int64
	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
			received.Add(1)
			return nil
		},
	}, defaultOutputConfig(), nil)

	ctx := context.Background()
	out.Start(ctx)
	out.Enqueue(newTestEvent())
	out.CloseQueue()
	out.WaitDone()

	assert.Equal(t, int64(1), received.Load())
	assert.Equal(t, int64(1), out.sentTotal.Load())
}

func TestOutputRetriesOnFailure(t *testing.T) {
	var attempts atomic.Int64
	cfg := defaultOutputConfig()
	cfg.Retry = RetryConfig{
		MaxAttempts:     4,
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     50 * time.Millisecond,
		Multiplier:      2.0,
	}

	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
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

func TestOutputFailsAfterMaxRetries(t *testing.T) {
	cfg := defaultOutputConfig()
	cfg.Retry = RetryConfig{
		MaxAttempts:     2,
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     10 * time.Millisecond,
		Multiplier:      1.0,
	}

	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
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

func TestOutputDropsWhenQueueFull(t *testing.T) {
	blocked := make(chan struct{})
	cfg := defaultOutputConfig()
	cfg.QueueSize = 2
	cfg.Workers = 1

	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
			<-blocked
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 5; i++ {
		out.Enqueue(newTestEvent())
	}

	assert.Greater(t, out.droppedTotal.Load(), int64(0))

	close(blocked)
	out.CloseQueue()
	out.WaitDone()
}

func TestOutputCircuitBreakerBlocks(t *testing.T) {
	var attempts atomic.Int64
	cfg := defaultOutputConfig()
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

	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(_ context.Context, _ *domain.Event) error {
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

func TestOutputGetStatus(t *testing.T) {
	out := NewOutput(&mockOutput{name: "slack"}, defaultOutputConfig(), nil)

	status := out.GetStatus()
	assert.Equal(t, "slack", status.Name)
	assert.Equal(t, 0, status.QueueDepth)
	assert.Equal(t, 100, status.QueueCapacity)
	assert.Equal(t, "closed", status.CircuitState)
}

func TestOutputForceStopOnContextCancel(t *testing.T) {
	out := NewOutput(&mockOutput{
		name: "test",
		sendFunc: func(ctx context.Context, _ *domain.Event) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}, defaultOutputConfig(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	out.Start(ctx)

	out.Enqueue(newTestEvent())
	time.Sleep(20 * time.Millisecond)

	cancel()
	out.WaitDone()
}
