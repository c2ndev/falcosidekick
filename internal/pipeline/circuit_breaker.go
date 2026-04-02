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
	"sync"
	"time"
)

// CircuitState represents the state of a circuit breaker.
type CircuitState int

const (
	// CircuitClosed allows requests through normally.
	CircuitClosed CircuitState = iota
	// CircuitOpen blocks all requests.
	CircuitOpen
	// CircuitHalfOpen allows exactly one probe request to test recovery.
	CircuitHalfOpen
)

// String returns the state name.
func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig holds circuit breaker thresholds.
type CircuitBreakerConfig struct {
	FailureThreshold int           `mapstructure:"failure_threshold"`
	SuccessThreshold int           `mapstructure:"success_threshold"`
	ResetTimeout     time.Duration `mapstructure:"reset_timeout"`
}

// CircuitBreaker implements the circuit breaker pattern per output.
type CircuitBreaker struct {
	lastFailure  time.Time
	cfg          CircuitBreakerConfig
	failureCount int
	successCount int
	state        CircuitState
	probing      bool
	mu           sync.Mutex
}

// NewCircuitBreaker creates a CircuitBreaker with the given thresholds.
func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 5
	}
	if cfg.SuccessThreshold <= 0 {
		cfg.SuccessThreshold = 2
	}
	if cfg.ResetTimeout <= 0 {
		cfg.ResetTimeout = 30 * time.Second
	}
	return &CircuitBreaker{cfg: cfg}
}

// GetState returns the current circuit state, transitioning from open to half-open
// when the reset timeout has elapsed.
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == CircuitOpen && time.Since(cb.lastFailure) > cb.cfg.ResetTimeout {
		cb.state = CircuitHalfOpen
		cb.successCount = 0
		cb.probing = false
	}
	return cb.state
}

// AllowRequest checks if a request should be allowed through.
// In closed state, always allows. In open state, always blocks.
// In half-open state, allows exactly one probe request at a time.
func (cb *CircuitBreaker) AllowRequest() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == CircuitOpen && time.Since(cb.lastFailure) > cb.cfg.ResetTimeout {
		cb.state = CircuitHalfOpen
		cb.successCount = 0
		cb.probing = false
	}

	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		return false
	case CircuitHalfOpen:
		if cb.probing {
			return false
		}
		cb.probing = true
		return true
	default:
		return false
	}
}

// RecordSuccess registers a successful request.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failureCount = 0
	cb.probing = false
	if cb.state == CircuitHalfOpen {
		cb.successCount++
		if cb.successCount >= cb.cfg.SuccessThreshold {
			cb.state = CircuitClosed
		}
	}
}

// RecordFailure registers a failed request.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.probing = false
	cb.failureCount++
	cb.lastFailure = time.Now()
	if cb.failureCount >= cb.cfg.FailureThreshold {
		cb.state = CircuitOpen
	}
}
