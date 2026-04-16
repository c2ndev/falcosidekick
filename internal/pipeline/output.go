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
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// OutputStatus holds observable counters and state for one output.
type OutputStatus struct {
	LastSuccess   time.Time `json:"last_success"`
	Name          string    `json:"name"`
	CircuitState  string    `json:"circuit_state"`
	LastError     string    `json:"last_error"`
	QueueDepth    int       `json:"queue_depth"`
	QueueCapacity int       `json:"queue_capacity"`
	SentTotal     int       `json:"sent_total"`
	DroppedTotal  int       `json:"dropped_total"`
	FailedTotal   int       `json:"failed_total"`
}

// Output is the runtime delivery unit for one output destination.
type Output struct {
	lastError      atomic.Value
	lastSuccess    atomic.Value
	driver         output.Driver
	batchSender    output.BatchSender
	metrics        core.MetricsCollector
	queue          chan *event.Event
	circuitBreaker *CircuitBreaker
	cancel         context.CancelFunc
	config         output.RuntimeConfig
	workerDone     sync.WaitGroup
	sentTotal      atomic.Int64
	droppedTotal   atomic.Int64
	failedTotal    atomic.Int64
}

// NewOutput creates a complete Output from a driver and configuration.
func NewOutput(driver output.Driver, cfg *output.RuntimeConfig, metrics core.MetricsCollector) *Output {
	o := &Output{
		driver:         driver,
		config:         *cfg,
		queue:          make(chan *event.Event, cfg.QueueSize),
		circuitBreaker: NewCircuitBreaker(cfg.CircuitBreaker),
		metrics:        metrics,
	}
	if bs, ok := driver.(output.BatchSender); ok && cfg.Batching != nil && cfg.Batching.Enabled {
		o.batchSender = bs
	}
	o.lastSuccess.Store(time.Time{})
	o.lastError.Store("")
	return o
}

// Name returns the output driver name.
func (o *Output) Name() string {
	return o.driver.Name()
}

// Driver returns the underlying driver.
func (o *Output) Driver() output.Driver {
	return o.driver
}

// Start launches the worker goroutines. A child context is derived from ctx
// so that Retire can cancel this output's workers independently.
func (o *Output) Start(ctx context.Context) {
	workerCtx, cancel := context.WithCancel(ctx) //nolint:gosec // cancel is stored in o.cancel and called by Retire
	o.cancel = cancel

	worker := o.runWorker
	if o.batchSender != nil {
		worker = o.runBatchWorker
	}
	for i := 0; i < o.config.Workers; i++ {
		o.workerDone.Add(1)
		go func() {
			defer o.workerDone.Done()
			worker(workerCtx)
		}()
	}
}

// Enqueue adds an event to the output queue. Drops the event if the queue is full.
func (o *Output) Enqueue(evt *event.Event) {
	select {
	case o.queue <- evt:
	default:
		o.droppedTotal.Add(1)
		if o.metrics != nil {
			o.metrics.RecordDrop(context.Background(), o.driver.Name())
		}
	}
}

// Close releases the underlying driver resources without draining.
// Use Retire for a graceful stop that drains the queue first.
func (o *Output) Close() error {
	return o.driver.Close()
}

// Retire closes the queue, drains bounded by ctx, then closes the driver.
// On deadline it cancels the worker context and returns; the driver close
// is deferred until workers actually exit. driver.Close is never invoked
// while a worker may still be in Send.
func (o *Output) Retire(ctx context.Context) error {
	close(o.queue)

	done := make(chan struct{})
	go func() {
		o.workerDone.Wait()
		close(done)
	}()

	select {
	case <-done:
		_ = o.driver.Close()
		return nil
	case <-ctx.Done():
	}

	if o.cancel != nil {
		o.cancel()
	}
	go func() {
		<-done
		_ = o.driver.Close()
	}()
	return fmt.Errorf("output %q: retire deadline exceeded, deferred close scheduled", o.driver.Name())
}

func (o *Output) closeQueue() {
	close(o.queue)
}

func (o *Output) waitDone() {
	o.workerDone.Wait()
}

// GetStatus returns a snapshot of this output's counters and state.
func (o *Output) GetStatus() OutputStatus {
	return OutputStatus{
		Name:          o.driver.Name(),
		QueueDepth:    len(o.queue),
		QueueCapacity: o.config.QueueSize,
		SentTotal:     int(o.sentTotal.Load()),
		DroppedTotal:  int(o.droppedTotal.Load()),
		FailedTotal:   int(o.failedTotal.Load()),
		CircuitState:  o.circuitBreaker.GetState().String(),
		LastSuccess:   o.lastSuccess.Load().(time.Time),
		LastError:     o.lastError.Load().(string),
	}
}

// executeWithRetry runs fn with circuit breaker and retry. On success it adds
// count to sentTotal; on final failure it adds count to failedTotal.
func (o *Output) executeWithRetry(ctx context.Context, count int64, sendFunc func(ctx context.Context) error) {
	if !o.circuitBreaker.AllowRequest() {
		o.failedTotal.Add(count)
		if o.metrics != nil {
			o.metrics.RecordOutput(ctx, o.driver.Name(), "circuit_open", 0)
		}
		return
	}

	var lastErr error
	for attempt := 0; attempt < o.config.Retry.MaxAttempts; attempt++ {
		if attempt > 0 {
			backoff := o.config.Retry.ComputeBackoff(attempt)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}

		start := time.Now()
		err := sendFunc(ctx)
		duration := time.Since(start)

		if err == nil {
			o.circuitBreaker.RecordSuccess()
			o.sentTotal.Add(count)
			o.lastSuccess.Store(time.Now())
			if o.metrics != nil {
				o.metrics.RecordOutput(ctx, o.driver.Name(), "ok", duration)
			}
			return
		}

		lastErr = err
		o.circuitBreaker.RecordFailure()
	}

	o.failedTotal.Add(count)
	o.lastError.Store(lastErr.Error())
	if o.metrics != nil {
		o.metrics.RecordOutput(ctx, o.driver.Name(), "error", 0)
		o.metrics.RecordError(ctx, o.driver.Name(), lastErr)
	}
}
