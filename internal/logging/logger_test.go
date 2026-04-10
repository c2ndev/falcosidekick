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

package logging

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLoggerValidLevels(t *testing.T) {
	levels := []LogLevel{TraceLevel, DebugLevel, InfoLevel, WarnLevel, ErrorLevel}
	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			logger, err := NewLogger(level, TextFormat)
			require.NoError(t, err)
			assert.NotNil(t, logger)
		})
	}
}

func TestNewLoggerValidFormats(t *testing.T) {
	formats := []LogFormat{TextFormat, JSONFormat}
	for _, format := range formats {
		t.Run(string(format), func(t *testing.T) {
			logger, err := NewLogger("info", format)
			require.NoError(t, err)
			assert.NotNil(t, logger)
		})
	}
}

func TestNewLoggerInvalidLevel(t *testing.T) {
	_, err := NewLogger("invalid", TextFormat)
	assert.Error(t, err)
}

func TestNewLoggerInvalidFormat(t *testing.T) {
	_, err := NewLogger("info", "invalid")
	assert.Error(t, err)
}

func TestLogLevelValidate(t *testing.T) {
	tests := []struct {
		level   LogLevel
		wantErr bool
	}{
		{TraceLevel, false},
		{DebugLevel, false},
		{InfoLevel, false},
		{WarnLevel, false},
		{ErrorLevel, false},
		{"invalid", true},
		{"", true},
	}
	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			errs := tt.level.Validate()
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestLogFormatValidate(t *testing.T) {
	tests := []struct {
		format  LogFormat
		wantErr bool
	}{
		{TextFormat, false},
		{JSONFormat, false},
		{"invalid", true},
		{"", true},
	}
	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			errs := tt.format.Validate()
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}
