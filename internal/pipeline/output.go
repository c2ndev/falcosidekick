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

// OutputConfig holds per-output settings including delivery and priority.
type OutputConfig struct {
	MinPriority    domain.Priority      `mapstructure:"minimumpriority"`
	CircuitBreaker CircuitBreakerConfig `mapstructure:"circuit_breaker"`
	Retry          RetryConfig          `mapstructure:"retry"`
	QueueSize      int                  `mapstructure:"queue_size"`
	Workers        int                  `mapstructure:"workers"`
}

// Validate checks output settings for errors.
func (c *OutputConfig) Validate() utils.ValidationErrors {
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

// Output is the complete runtime delivery unit for one output destination.
// It wraps an OutputDriver with a queue, worker pool, retry, and circuit breaker.
type Output struct {
	lastError      atomic.Value
	lastSuccess    atomic.Value
	driver         domain.OutputDriver
	metrics        domain.MetricsCollector
	queue          chan *domain.Event
	circuitBreaker *CircuitBreaker
	config         OutputConfig
	workerDone     sync.WaitGroup
	sentTotal      atomic.Int64
	droppedTotal   atomic.Int64
	failedTotal    atomic.Int64
}

// NewOutput creates a complete Output from a driver and configuration.
func NewOutput(driver domain.OutputDriver, cfg *OutputConfig, metrics domain.MetricsCollector) *Output {
	o := &Output{
		driver:         driver,
		config:         *cfg,
		queue:          make(chan *domain.Event, cfg.QueueSize),
		circuitBreaker: NewCircuitBreaker(cfg.CircuitBreaker),
		metrics:        metrics,
	}
	o.lastSuccess.Store(time.Time{})
	o.lastError.Store("")
	return o
}

// Name returns the output driver name.
func (o *Output) Name() string {
	return o.driver.Name()
}

// Start launches the worker goroutines.
func (o *Output) Start(ctx context.Context) {
	for i := 0; i < o.config.Workers; i++ {
		o.workerDone.Add(1)
		go func() {
			defer o.workerDone.Done()
			o.runWorker(ctx)
		}()
	}
}

// Enqueue adds an event to the output queue. Drops the event if the queue is full.
func (o *Output) Enqueue(event *domain.Event) {
	select {
	case o.queue <- event:
	default:
		o.droppedTotal.Add(1)
		if o.metrics != nil {
			o.metrics.RecordDrop(context.Background(), o.driver.Name())
		}
	}
}

// Close releases the underlying driver resources.
func (o *Output) Close() error {
	return o.driver.Close()
}

// CloseQueue closes the event channel. Workers finish remaining events then exit.
func (o *Output) CloseQueue() {
	close(o.queue)
}

// WaitDone blocks until all worker goroutines have exited.
func (o *Output) WaitDone() {
	o.workerDone.Wait()
}

// GetStatus returns observable state for the UI.
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

func (o *Output) runWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-o.queue:
			if !ok {
				return
			}
			o.sendWithRetry(ctx, event)
		}
	}
}

func (o *Output) sendWithRetry(ctx context.Context, event *domain.Event) {
	if !o.circuitBreaker.AllowRequest() {
		o.failedTotal.Add(1)
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
		err := o.driver.Send(ctx, event)
		duration := time.Since(start)

		if err == nil {
			o.circuitBreaker.RecordSuccess()
			o.sentTotal.Add(1)
			o.lastSuccess.Store(time.Now())
			if o.metrics != nil {
				o.metrics.RecordOutput(ctx, o.driver.Name(), "ok", duration)
			}
			return
		}

		lastErr = err
		o.circuitBreaker.RecordFailure()
	}

	o.failedTotal.Add(1)
	o.lastError.Store(lastErr.Error())
	if o.metrics != nil {
		o.metrics.RecordOutput(ctx, o.driver.Name(), "error", 0)
		o.metrics.RecordError(ctx, o.driver.Name(), lastErr)
	}
}
