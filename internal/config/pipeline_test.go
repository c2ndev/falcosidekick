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

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
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
	resolved := cfg.Pipeline.ResolveOutputConfig("nonexistent")

	assert.Equal(t, cfg.Pipeline.OutputConfig, resolved)
}

func TestResolveOutputConfigUnknownOutput(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"slack": {"webhookurl": "https://hooks.slack.com/xxx"},
	}

	resolved := cfg.Pipeline.ResolveOutputConfig("webhook")
	assert.Equal(t, cfg.Pipeline.QueueSize, resolved.QueueSize, "unknown output returns pipeline defaults")
}

func TestResolveOutputConfigOverrides(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Outputs = map[string]map[string]any{
		"es": {
			"queue_size":      5000,
			"workers":         4,
			"minimumpriority": "warning",
		},
	}

	resolved := cfg.Pipeline.ResolveOutputConfig("es")
	assert.Equal(t, 5000, resolved.QueueSize)
	assert.Equal(t, 4, resolved.Workers)
	assert.Equal(t, domain.PriorityWarning, resolved.MinPriority)
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

	resolved := cfg.Pipeline.ResolveOutputConfig("es")
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

	resolved := cfg.Pipeline.ResolveOutputConfig("loki")
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

	resolved := cfg.Pipeline.ResolveOutputConfig("test")
	assert.Equal(t, cfg.Pipeline.QueueSize, resolved.QueueSize, "invalid type must not override")
	assert.Equal(t, cfg.Pipeline.Workers, resolved.Workers, "invalid type must not override")
}

func TestValidateDelegatesBatching(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.Pipeline.Batching = pipeline.BatchingConfig{Enabled: true, BatchSize: -1}

	errs := cfg.Validate()
	require.NotEmpty(t, errs)
}
