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
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// PipelineConfig holds event pipeline settings. Uses pipeline package types directly.
type PipelineConfig struct {
	Outputs                     map[string]map[string]any `mapstructure:"outputs"`
	Enricher                    pipeline.EnricherConfig   `mapstructure:"enricher"`
	pipeline.OutputWorkerConfig `mapstructure:",squash"`
}

// Validate checks the pipeline configuration for errors.
func (c *PipelineConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors

	errs.Merge("enricher", c.Enricher.Validate())
	errs.Merge("", c.OutputWorkerConfig.Validate())

	if len(errs) > 0 {
		return errs
	}
	return nil
}
