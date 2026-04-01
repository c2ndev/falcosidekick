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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCircuitBreakerStartsClosed(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{})
	assert.Equal(t, CircuitClosed, cb.GetState())
}

func TestCircuitBreakerDefaults(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{})
	assert.Equal(t, 5, cb.cfg.FailureThreshold)
	assert.Equal(t, 2, cb.cfg.SuccessThreshold)
	assert.Equal(t, 30*time.Second, cb.cfg.ResetTimeout)
}

func TestCircuitBreakerOpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 3})

	cb.RecordFailure()
	assert.Equal(t, CircuitClosed, cb.GetState())
	cb.RecordFailure()
	assert.Equal(t, CircuitClosed, cb.GetState())
	cb.RecordFailure()
	assert.Equal(t, CircuitOpen, cb.GetState())
}

func TestCircuitBreakerTransitionsToHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		ResetTimeout:     50 * time.Millisecond,
	})

	cb.RecordFailure()
	assert.Equal(t, CircuitOpen, cb.GetState())

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, CircuitHalfOpen, cb.GetState())
}

func TestCircuitBreakerClosesAfterSuccessInHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 2,
		ResetTimeout:     50 * time.Millisecond,
	})

	cb.RecordFailure()
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, CircuitHalfOpen, cb.GetState())

	cb.RecordSuccess()
	assert.Equal(t, CircuitHalfOpen, cb.GetState())
	cb.RecordSuccess()
	assert.Equal(t, CircuitClosed, cb.GetState())
}

func TestCircuitBreakerSuccessResetFailureCount(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 3})

	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess()
	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, CircuitClosed, cb.GetState())
}

func TestCircuitBreakerReopensOnFailureInHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		ResetTimeout:     50 * time.Millisecond,
	})

	cb.RecordFailure()
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, CircuitHalfOpen, cb.GetState())

	cb.RecordFailure()
	assert.Equal(t, CircuitOpen, cb.GetState())
}

func TestCircuitStateString(t *testing.T) {
	tests := []struct {
		want  string
		state CircuitState
	}{
		{"closed", CircuitClosed},
		{"open", CircuitOpen},
		{"half-open", CircuitHalfOpen},
		{"unknown", CircuitState(99)},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.state.String())
		})
	}
}
