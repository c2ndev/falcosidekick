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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestRuntimeDefaultsValidateValid(t *testing.T) {
	cfg := defaultRuntimeDefaults()
	assert.Empty(t, cfg.Validate())
}

func TestRuntimeDefaultsValidateZeroValues(t *testing.T) {
	cfg := output.RuntimeConfig{}
	assert.NotEmpty(t, cfg.Validate())
}

func TestRuntimeDefaultsValidateNegativeQueueSize(t *testing.T) {
	cfg := defaultRuntimeDefaults()
	cfg.QueueSize = -1
	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
}

func TestOutputGetStatus(t *testing.T) {
	out := NewOutput(&testutil.MockDriver{DriverName: "slack"}, defaultRuntimeDefaults(), nil)

	status := out.GetStatus()
	assert.Equal(t, "slack", status.Name)
	assert.Equal(t, 0, status.QueueDepth)
	assert.Equal(t, 100, status.QueueCapacity)
	assert.Equal(t, "closed", status.CircuitState)
}

func TestRetireGraceful(t *testing.T) {
	var calls atomic.Int64
	var closeCalled atomic.Bool

	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			calls.Add(1)
			return nil
		},
		CloseFunc: func() error {
			closeCalled.Store(true)
			return nil
		},
	}, defaultRuntimeDefaults(), nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 5; i++ {
		out.Enqueue(newTestEvent())
	}

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()

	err := out.Retire(retireCtx)
	require.NoError(t, err)

	assert.Equal(t, int64(5), calls.Load(), "all queued events must be processed")
	assert.True(t, closeCalled.Load(), "driver Close must be called")
}

func TestRetireDeadlineExceeded(t *testing.T) {
	var closeCalled atomic.Bool

	out := NewOutput(&testutil.MockDriver{
		DriverName: "stuck",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			// Ignore context cancellation: block forever.
			select {}
		},
		CloseFunc: func() error {
			closeCalled.Store(true)
			return nil
		},
	}, defaultRuntimeDefaults(), nil)

	out.Start(context.Background())
	out.Enqueue(newTestEvent())

	// Let the worker pick up the event and enter the blocking Send.
	time.Sleep(20 * time.Millisecond)

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer retireCancel()

	start := time.Now()
	err := out.Retire(retireCtx)
	elapsed := time.Since(start)

	require.Error(t, err, "Retire must return error when deadline exceeded")
	assert.Contains(t, err.Error(), "deadline exceeded")
	assert.Less(t, elapsed, 2*time.Second, "Retire must be bounded, not hang forever")

	// Driver Close is deferred until the worker eventually exits. It may or
	// may not have been called yet depending on goroutine scheduling.
}

func TestRetireDoesNotCloseDriverBeforeWorkerExit(t *testing.T) {
	var mu sync.Mutex
	var closeOrder []string

	sendStarted := make(chan struct{})
	sendBlock := make(chan struct{})

	out := NewOutput(&testutil.MockDriver{
		DriverName: "ordered",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			close(sendStarted)
			<-sendBlock
			mu.Lock()
			closeOrder = append(closeOrder, "worker-exit")
			mu.Unlock()
			return nil
		},
		CloseFunc: func() error {
			mu.Lock()
			closeOrder = append(closeOrder, "driver-close")
			mu.Unlock()
			return nil
		},
	}, defaultRuntimeDefaults(), nil)

	out.Start(context.Background())
	out.Enqueue(newTestEvent())
	<-sendStarted

	// Retire with generous deadline so drain succeeds.
	retireDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		retireDone <- out.Retire(ctx)
	}()

	// Unblock the worker.
	close(sendBlock)

	err := <-retireDone
	require.NoError(t, err)

	// Allow goroutines to settle.
	time.Sleep(20 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, closeOrder, 2)
	assert.Equal(t, "worker-exit", closeOrder[0], "worker must exit before driver.Close is called")
	assert.Equal(t, "driver-close", closeOrder[1], "driver.Close must be called after worker exits")
}

func TestOutputDropsWhenQueueFull(t *testing.T) {
	blocked := make(chan struct{})
	cfg := defaultRuntimeDefaults()
	cfg.QueueSize = 2
	cfg.Workers = 1

	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(_ context.Context, _ *event.Event) error {
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

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()
	_ = out.Retire(retireCtx)
}
