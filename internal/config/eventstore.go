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
	"fmt"

	"github.com/falcosecurity/falcosidekick/internal/store"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// StoreBackend identifies the event store implementation.
type StoreBackend string

// Supported event store backends.
const (
	MemoryStore   StoreBackend = "memory"
	SQLiteStore   StoreBackend = "sqlite"
	PostgresStore StoreBackend = "postgres"
	RedisStore    StoreBackend = "redis"
)

var validStoreBackends = map[StoreBackend]bool{
	MemoryStore: true, SQLiteStore: true, PostgresStore: true, RedisStore: true,
}

// EventStoreConfig holds event store backend selection and settings.
type EventStoreConfig struct {
	Memory  *store.MemoryConfig `mapstructure:"memory,omitempty"`
	Backend StoreBackend        `mapstructure:"backend"`
}

// Validate checks the event store configuration for errors.
func (c *EventStoreConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors

	if !validStoreBackends[c.Backend] {
		errs.Add("backend", fmt.Sprintf("must be memory/sqlite/postgres/redis, got %q", c.Backend))
		return errs
	}

	switch c.Backend {
	case MemoryStore:
		if c.Memory == nil {
			errs.Add("memory", "memory section required when backend is memory")
		} else {
			errs.Merge("memory", c.Memory.Validate())
		}
	case SQLiteStore, PostgresStore, RedisStore:
		// Future backends - config validated when implemented.
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}
