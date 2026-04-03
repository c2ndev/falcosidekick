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
	"github.com/stretchr/testify/require"
)

func TestValidateStoreBackend(t *testing.T) {
	tests := []struct {
		backend StoreBackend
		wantErr bool
	}{
		{MemoryStore, false},
		{SQLiteStore, false},
		{PostgresStore, false},
		{RedisStore, false},
		{StoreBackend(invalidValue), true},
		{StoreBackend(""), true},
	}

	for _, tt := range tests {
		t.Run(string(tt.backend), func(t *testing.T) {
			cfg := loadDefaults(t)
			cfg.EventStore.Backend = tt.backend
			errs := cfg.Validate()
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestValidateDelegatesMemoryStore(t *testing.T) {
	cfg := loadDefaults(t)
	require.NotNil(t, cfg.EventStore.Memory)
	cfg.EventStore.Memory.Capacity = -1

	errs := cfg.Validate()
	assert.NotEmpty(t, errs)

	found := false
	for _, e := range errs {
		if assert.ObjectsAreEqual("capacity", e.Field) || assert.ObjectsAreEqual("eventstore.memory.capacity", e.Field) {
			found = true
			break
		}
	}
	assert.True(t, found, "expected error about memory capacity, got: %v", errs)
}
