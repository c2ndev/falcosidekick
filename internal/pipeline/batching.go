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
	"fmt"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// BatchingConfig holds per-output batching settings.
type BatchingConfig struct {
	FlushInterval time.Duration `mapstructure:"flush_interval"`
	BatchSize     int           `mapstructure:"batch_size"`
	Enabled       bool          `mapstructure:"enabled"`
}

// Validate checks batching settings for errors.
func (c *BatchingConfig) Validate() utils.ValidationErrors {
	if !c.Enabled {
		return nil
	}
	var errs utils.ValidationErrors
	if c.BatchSize <= 0 {
		errs.Add("batch_size", fmt.Sprintf("must be positive when enabled, got %d", c.BatchSize))
	}
	if c.FlushInterval <= 0 {
		errs.Add("flush_interval", fmt.Sprintf("must be positive when enabled, got %s", c.FlushInterval))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}
