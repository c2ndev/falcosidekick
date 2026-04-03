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

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateDelegatesRetry(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Retry.MaxAttempts = -1

	errs := cfg.Validate()
	assert.NotEmpty(t, errs)

	found := false
	for _, e := range errs {
		if assert.ObjectsAreEqual("retry.max_attempts", e.Field) || assert.ObjectsAreEqual("pipeline.retry.max_attempts", e.Field) {
			found = true
			break
		}
	}
	assert.True(t, found, "expected error about retry.max_attempts, got: %v", errs)
}

func TestValidateDelegatesCircuitBreaker(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.CircuitBreaker.FailureThreshold = -1

	errs := cfg.Validate()
	assert.NotEmpty(t, errs)

	found := false
	for _, e := range errs {
		if assert.ObjectsAreEqual("circuit_breaker.failure_threshold", e.Field) || assert.ObjectsAreEqual("pipeline.circuit_breaker.failure_threshold", e.Field) {
			found = true
			break
		}
	}
	assert.True(t, found, "expected error about circuit_breaker.failure_threshold, got: %v", errs)
}

func TestValidateEnricherThresholds(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Enricher.TruncateEventThreshold = -1

	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
}
