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

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// OutputStatus holds observable state for the UI pipeline view.
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

// OutputWorkerConfig holds per-output worker pool settings.
type OutputWorkerConfig struct {
	CircuitBreaker CircuitBreakerConfig `mapstructure:"circuit_breaker"`
	Retry          RetryConfig          `mapstructure:"retry"`
	QueueSize      int                  `mapstructure:"queue_size"`
	Workers        int                  `mapstructure:"workers"`
}

// Validate checks worker pool settings for errors.
func (c *OutputWorkerConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors

	if c.QueueSize <= 0 {
		errs.Add("queue_size", fmt.Sprintf("must be positive, got %d", c.QueueSize))
	}
	if c.Workers <= 0 {
		errs.Add("workers", fmt.Sprintf("must be positive, got %d", c.Workers))
	}
	errs.Merge("circuit_breaker", c.CircuitBreaker.Validate())
	errs.Merge("retry", c.Retry.Validate())

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// OutputWorker manages a per-output queue, worker pool, circuit breaker, and retry.
type OutputWorker struct {
	lastError      atomic.Value
	output         domain.Output
	metrics        domain.MetricsCollector
	lastSuccess    atomic.Value
	queue          chan *domain.Event
	circuitBreaker *CircuitBreaker
	workerDone     sync.WaitGroup
	retry          RetryConfig
	queueCapacity  int
	workerCount    int
	sentTotal      atomic.Int64
	droppedTotal   atomic.Int64
	failedTotal    atomic.Int64
}

// NewOutputWorker creates an OutputWorker for the given output.
func NewOutputWorker(output domain.Output, cfg OutputWorkerConfig, metrics domain.MetricsCollector) *OutputWorker {
	w := &OutputWorker{
		output:         output,
		queue:          make(chan *domain.Event, cfg.QueueSize),
		queueCapacity:  cfg.QueueSize,
		workerCount:    cfg.Workers,
		circuitBreaker: NewCircuitBreaker(cfg.CircuitBreaker),
		retry:          cfg.Retry,
		metrics:        metrics,
	}
	w.lastSuccess.Store(time.Time{})
	w.lastError.Store("")
	return w
}

// Start launches the worker goroutines.
func (w *OutputWorker) Start(ctx context.Context) {
	for i := 0; i < w.workerCount; i++ {
		w.workerDone.Add(1)
		go func() {
			defer w.workerDone.Done()
			w.runWorker(ctx)
		}()
	}
}

// Enqueue adds an event to the output queue. Drops the event if the queue is full.
func (w *OutputWorker) Enqueue(event *domain.Event) {
	select {
	case w.queue <- event:
	default:
		w.droppedTotal.Add(1)
		if w.metrics != nil {
			w.metrics.RecordDrop(context.Background(), w.output.Name())
		}
	}
}

// CloseQueue closes the event channel. Workers finish remaining events then exit.
func (w *OutputWorker) CloseQueue() {
	close(w.queue)
}

// WaitDone blocks until all worker goroutines have exited.
func (w *OutputWorker) WaitDone() {
	w.workerDone.Wait()
}

// GetStatus returns observable state for the UI.
func (w *OutputWorker) GetStatus() OutputStatus {
	return OutputStatus{
		Name:          w.output.Name(),
		QueueDepth:    len(w.queue),
		QueueCapacity: w.queueCapacity,
		SentTotal:     int(w.sentTotal.Load()),
		DroppedTotal:  int(w.droppedTotal.Load()),
		FailedTotal:   int(w.failedTotal.Load()),
		CircuitState:  w.circuitBreaker.GetState().String(),
		LastSuccess:   w.lastSuccess.Load().(time.Time),
		LastError:     w.lastError.Load().(string),
	}
}

func (w *OutputWorker) runWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-w.queue:
			if !ok {
				return
			}
			w.sendWithRetry(ctx, event)
		}
	}
}

func (w *OutputWorker) sendWithRetry(ctx context.Context, event *domain.Event) {
	if !w.circuitBreaker.AllowRequest() {
		w.failedTotal.Add(1)
		if w.metrics != nil {
			w.metrics.RecordOutput(ctx, w.output.Name(), "circuit_open", 0)
		}
		return
	}

	var lastErr error
	for attempt := 0; attempt < w.retry.MaxAttempts; attempt++ {
		if attempt > 0 {
			backoff := w.retry.ComputeBackoff(attempt)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}

		start := time.Now()
		err := w.output.Send(ctx, event)
		duration := time.Since(start)

		if err == nil {
			w.circuitBreaker.RecordSuccess()
			w.sentTotal.Add(1)
			w.lastSuccess.Store(time.Now())
			if w.metrics != nil {
				w.metrics.RecordOutput(ctx, w.output.Name(), "ok", duration)
			}
			return
		}

		lastErr = err
		w.circuitBreaker.RecordFailure()
	}

	w.failedTotal.Add(1)
	w.lastError.Store(lastErr.Error())
	if w.metrics != nil {
		w.metrics.RecordOutput(ctx, w.output.Name(), "error", 0)
		w.metrics.RecordError(ctx, w.output.Name(), lastErr)
	}
}
