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

func TestRetryConfigDefaults(t *testing.T) {
	cfg := RetryConfig{}
	cfg.ApplyDefaults()

	assert.Equal(t, 3, cfg.MaxAttempts)
	assert.Equal(t, 1*time.Second, cfg.InitialInterval)
	assert.Equal(t, 30*time.Second, cfg.MaxInterval)
	assert.Equal(t, 2.0, cfg.Multiplier)
}

func TestRetryConfigPreservesValues(t *testing.T) {
	cfg := RetryConfig{
		MaxAttempts:     5,
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     10 * time.Second,
		Multiplier:      3.0,
	}
	cfg.ApplyDefaults()

	assert.Equal(t, 5, cfg.MaxAttempts)
	assert.Equal(t, 500*time.Millisecond, cfg.InitialInterval)
	assert.Equal(t, 10*time.Second, cfg.MaxInterval)
	assert.Equal(t, 3.0, cfg.Multiplier)
}

func TestComputeBackoffExponential(t *testing.T) {
	cfg := RetryConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
	}

	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 1 * time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 16 * time.Second},
		{6, 30 * time.Second},
		{7, 30 * time.Second},
	}

	for _, tt := range tests {
		got := cfg.ComputeBackoff(tt.attempt)
		assert.Equal(t, tt.want, got, "attempt %d", tt.attempt)
	}
}

func TestComputeBackoffCapsAtMax(t *testing.T) {
	cfg := RetryConfig{
		InitialInterval: 10 * time.Second,
		MaxInterval:     15 * time.Second,
		Multiplier:      2.0,
	}

	assert.Equal(t, 10*time.Second, cfg.ComputeBackoff(1))
	assert.Equal(t, 15*time.Second, cfg.ComputeBackoff(2))
	assert.Equal(t, 15*time.Second, cfg.ComputeBackoff(10))
}
