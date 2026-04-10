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
)

const invalidValue = "invalid"

func loadDefaults(t *testing.T) *Config {
	t.Helper()
	cfg, err := Load("")
	require.NoError(t, err)
	return cfg
}

func TestDefaultPipelineEnricherFromConfig(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)

	assert.Equal(t, 4096, cfg.Pipeline.Enricher.TruncateEventThreshold)
	assert.Equal(t, 512, cfg.Pipeline.Enricher.TruncateFieldThreshold)
}

func TestDefaultPipelineWorkerFromConfig(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)

	assert.Equal(t, 1000, cfg.Pipeline.QueueSize)
	assert.Equal(t, 2, cfg.Pipeline.Workers)
	assert.Equal(t, 3, cfg.Pipeline.Retry.MaxAttempts)
	assert.Equal(t, time.Second, cfg.Pipeline.Retry.InitialInterval)
	assert.Equal(t, 30*time.Second, cfg.Pipeline.Retry.MaxInterval)
	assert.Equal(t, 2.0, cfg.Pipeline.Retry.Multiplier)
	assert.Equal(t, 5, cfg.Pipeline.CircuitBreaker.FailureThreshold)
	assert.Equal(t, 2, cfg.Pipeline.CircuitBreaker.SuccessThreshold)
	assert.Equal(t, 30*time.Second, cfg.Pipeline.CircuitBreaker.ResetTimeout)
}

func TestDefaultUIFromConfig(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)

	assert.False(t, cfg.UI.Enabled)
	assert.Equal(t, "memory", cfg.UI.Backend)
}

func TestDefaultTLSFromConfig(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)

	assert.Nil(t, cfg.TLS)
}

func TestDefaultsPassValidation(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)

	errs := cfg.Validate()
	assert.Empty(t, errs)
}

func TestValidatePortRange(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"valid", 2801, false},
		{"min", 1, false},
		{"max", 65535, false},
		{"zero", 0, true},
		{"negative", -1, true},
		{"too large", 65536, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := loadDefaults(t)
			cfg.ListenPort = tt.port
			errs := cfg.Validate()
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.ListenPort = 0
	cfg.LogLevel = invalidValue
	cfg.LogFormat = invalidValue

	errs := cfg.Validate()
	assert.GreaterOrEqual(t, len(errs), 3)
}

func TestValidateTLSNilPassesCleanly(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.TLS = nil

	errs := cfg.Validate()
	assert.Empty(t, errs)
}
