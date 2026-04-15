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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
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

func TestResolveOutputConfigDefaults(t *testing.T) {
	cfg := loadDefaults(t)
	resolved, _ := cfg.Pipeline.ResolveOutputConfig("nonexistent")

	assert.Equal(t, cfg.Pipeline.Config, resolved)
}

func TestResolveOutputConfigUnknownOutput(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"slack": {"webhookurl": "https://hooks.slack.com/xxx"},
	}

	resolved, _ := cfg.Pipeline.ResolveOutputConfig("webhook")
	assert.Equal(t, cfg.Pipeline.QueueSize, resolved.QueueSize, "unknown output returns pipeline defaults")
}

func TestResolveOutputConfigOverrides(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"es": {
			"queue_size":       5000,
			"workers":          4,
			"minimum_priority": "warning",
		},
	}

	resolved, _ := cfg.Pipeline.ResolveOutputConfig("es")
	assert.Equal(t, 5000, resolved.QueueSize)
	assert.Equal(t, 4, resolved.Workers)
	assert.Equal(t, event.PriorityWarning, resolved.MinPriority)
}

func TestResolveOutputConfigBatchingOverrides(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"es": {
			"batching": map[string]any{
				"enabled":    true,
				"batch_size": 1000,
			},
		},
	}

	resolved, _ := cfg.Pipeline.ResolveOutputConfig("es")
	assert.True(t, resolved.Batching.Enabled)
	assert.Equal(t, 1000, resolved.Batching.BatchSize)
}

func TestResolveOutputConfigBatchingFlushInterval(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"loki": {
			"batching": map[string]any{
				"enabled":        true,
				"flush_interval": 5 * time.Second,
			},
		},
	}

	resolved, _ := cfg.Pipeline.ResolveOutputConfig("loki")
	assert.Equal(t, 5*time.Second, resolved.Batching.FlushInterval)
}

func TestResolveOutputConfigIgnoresInvalidTypes(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"test": {
			"queue_size": "not_an_int",
			"workers":    "also_not_int",
		},
	}

	resolved, _ := cfg.Pipeline.ResolveOutputConfig("test")
	assert.Equal(t, cfg.Pipeline.QueueSize, resolved.QueueSize, "invalid type must not override")
	assert.Equal(t, cfg.Pipeline.Workers, resolved.Workers, "invalid type must not override")
}

func TestResolveOutputConfigInvalidPriority(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"webhook": {"minimum_priority": "invalid_priority"},
	}

	_, err := cfg.Pipeline.ResolveOutputConfig("webhook")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "webhook")
}

func TestResolveOutputConfigInvalidBatchingOverride(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"webhook": {
			"batching": map[string]any{
				"enabled":    true,
				"batch_size": -1,
			},
		},
	}

	_, err := cfg.Pipeline.ResolveOutputConfig("webhook")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "batch_size")
}

func TestValidateDelegatesBatching(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Batching = &output.BatchingConfig{Enabled: true, BatchSize: -1}

	errs := cfg.Validate()
	require.NotEmpty(t, errs)
}

func TestResolveOutputConfigRetryOverride(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"webhook": {
			"retry": map[string]any{
				"max_attempts":     5,
				"initial_interval": "2s",
				"max_interval":     "60s",
				"multiplier":       3.0,
			},
		},
	}

	resolved, err := cfg.Pipeline.ResolveOutputConfig("webhook")
	require.NoError(t, err)
	assert.Equal(t, 5, resolved.Retry.MaxAttempts)
	assert.Equal(t, 2*time.Second, resolved.Retry.InitialInterval)
	assert.Equal(t, 60*time.Second, resolved.Retry.MaxInterval)
	assert.Equal(t, 3.0, resolved.Retry.Multiplier)
}

func TestResolveOutputConfigCircuitBreakerOverride(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"webhook": {
			"circuit_breaker": map[string]any{
				"failure_threshold": 10,
				"success_threshold": 3,
				"reset_timeout":     "60s",
			},
		},
	}

	resolved, err := cfg.Pipeline.ResolveOutputConfig("webhook")
	require.NoError(t, err)
	assert.Equal(t, 10, resolved.CircuitBreaker.FailureThreshold)
	assert.Equal(t, 3, resolved.CircuitBreaker.SuccessThreshold)
	assert.Equal(t, 60*time.Second, resolved.CircuitBreaker.ResetTimeout)
}

func TestResolveOutputConfigDisableBatching(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Batching = &output.BatchingConfig{
		Enabled:       true,
		BatchSize:     500,
		FlushInterval: time.Second,
	}
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"webhook": {
			"batching": map[string]any{
				"enabled": false,
			},
		},
	}

	resolved, err := cfg.Pipeline.ResolveOutputConfig("webhook")
	require.NoError(t, err)
	assert.False(t, resolved.Batching.Enabled, "per-output batching.enabled=false must override pipeline default")
}

func TestResolveOutputConfigPartialRetryOverride(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"webhook": {
			"retry": map[string]any{
				"max_attempts": 10,
			},
		},
	}

	resolved, err := cfg.Pipeline.ResolveOutputConfig("webhook")
	require.NoError(t, err)
	assert.Equal(t, 10, resolved.Retry.MaxAttempts, "overridden field must change")
	assert.Equal(t, cfg.Pipeline.Retry.InitialInterval, resolved.Retry.InitialInterval, "non-overridden field must keep default")
	assert.Equal(t, cfg.Pipeline.Retry.MaxInterval, resolved.Retry.MaxInterval, "non-overridden field must keep default")
	assert.Equal(t, cfg.Pipeline.Retry.Multiplier, resolved.Retry.Multiplier, "non-overridden field must keep default")
}

func TestResolveOutputConfigPartialCircuitBreakerOverride(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"webhook": {
			"circuit_breaker": map[string]any{
				"failure_threshold": 20,
			},
		},
	}

	resolved, err := cfg.Pipeline.ResolveOutputConfig("webhook")
	require.NoError(t, err)
	assert.Equal(t, 20, resolved.CircuitBreaker.FailureThreshold, "overridden field must change")
	assert.Equal(t, cfg.Pipeline.CircuitBreaker.SuccessThreshold, resolved.CircuitBreaker.SuccessThreshold, "non-overridden field must keep default")
	assert.Equal(t, cfg.Pipeline.CircuitBreaker.ResetTimeout, resolved.CircuitBreaker.ResetTimeout, "non-overridden field must keep default")
}

func TestResolveOutputConfigPartialBatchingOverride(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Batching = &output.BatchingConfig{
		Enabled:       true,
		BatchSize:     500,
		FlushInterval: time.Second,
	}
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"webhook": {
			"batching": map[string]any{
				"batch_size": 2000,
			},
		},
	}

	resolved, err := cfg.Pipeline.ResolveOutputConfig("webhook")
	require.NoError(t, err)
	require.NotNil(t, resolved.Batching)
	assert.Equal(t, 2000, resolved.Batching.BatchSize, "overridden field must change")
	assert.True(t, resolved.Batching.Enabled, "non-overridden enabled must keep default")
	assert.Equal(t, time.Second, resolved.Batching.FlushInterval, "non-overridden flush_interval must keep default")
}

func TestResolveOutputConfigDoesNotMutateDefaults(t *testing.T) {
	cfg := loadDefaults(t)
	originalMaxAttempts := cfg.Pipeline.Retry.MaxAttempts
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"webhook": {
			"retry": map[string]any{
				"max_attempts": 99,
			},
		},
	}

	_, err := cfg.Pipeline.ResolveOutputConfig("webhook")
	require.NoError(t, err)
	assert.Equal(t, originalMaxAttempts, cfg.Pipeline.Retry.MaxAttempts, "pipeline defaults must not be mutated by resolve")
}
