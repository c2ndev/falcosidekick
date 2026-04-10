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

import "github.com/falcosecurity/falcosidekick/internal/utils"

// UIConfig holds UI settings.
type UIConfig struct {
	Backend string `mapstructure:"backend"`
	Enabled bool   `mapstructure:"enabled"`
}

// Validate checks the UI configuration for correctness.
func (c *UIConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.Enabled && c.Backend == "" {
		errs.Add("backend", "is required when UI is enabled")
	}
	return errs
}
