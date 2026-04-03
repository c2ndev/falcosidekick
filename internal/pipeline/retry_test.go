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

func TestRetryConfigValidateValid(t *testing.T) {
	cfg := RetryConfig{
		MaxAttempts:     3,
		InitialInterval: 1 * time.Second,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
	}
	assert.Empty(t, cfg.Validate())
}

func TestRetryConfigValidateZeroValues(t *testing.T) {
	cfg := RetryConfig{}
	assert.NotEmpty(t, cfg.Validate())
}

func TestRetryConfigValidateNegative(t *testing.T) {
	cfg := RetryConfig{MaxAttempts: -1}
	assert.NotEmpty(t, cfg.Validate())
}

func TestRetryConfigValidatePartialInvalid(t *testing.T) {
	cfg := RetryConfig{
		MaxAttempts:     3,
		InitialInterval: 1 * time.Second,
		MaxInterval:     0,
		Multiplier:      2.0,
	}
	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
	assert.Len(t, errs, 1)
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
