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
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// PipelineConfig holds event pipeline settings.
type PipelineConfig struct {
	Outputs               map[string]map[string]any `mapstructure:"outputs"`
	Enricher              pipeline.EnricherConfig   `mapstructure:"enricher"`
	pipeline.OutputConfig `mapstructure:",squash"`
}

// Validate checks the pipeline configuration for errors.
func (c *PipelineConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors

	errs.Merge("enricher", c.Enricher.Validate())
	errs.Merge("", c.OutputConfig.Validate())

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ResolveOutputConfig returns a fully resolved OutputConfig for the named output,
// merging pipeline defaults with per-output overrides and priority.
func (c *PipelineConfig) ResolveOutputConfig(name string) pipeline.OutputConfig {
	resolved := c.OutputConfig

	outputCfg, ok := c.Outputs[name]
	if !ok {
		return resolved
	}

	if v, ok := outputCfg["queue_size"]; ok {
		if n, ok := v.(int); ok && n > 0 {
			resolved.QueueSize = n
		}
	}
	if v, ok := outputCfg["workers"]; ok {
		if n, ok := v.(int); ok && n > 0 {
			resolved.Workers = n
		}
	}
	if v, ok := outputCfg["minimumpriority"]; ok {
		if s, ok := v.(string); ok && s != "" {
			resolved.MinPriority = domain.Priority(s)
		}
	}

	if v, ok := outputCfg["batching"]; ok {
		if bm, ok := v.(map[string]any); ok {
			if enabled, ok := bm["enabled"]; ok {
				if b, ok := enabled.(bool); ok {
					resolved.Batching.Enabled = b
				}
			}
			if bs, ok := bm["batch_size"]; ok {
				if n, ok := bs.(int); ok && n > 0 {
					resolved.Batching.BatchSize = n
				}
			}
			if fi, ok := bm["flush_interval"]; ok {
				if d, ok := fi.(time.Duration); ok && d > 0 {
					resolved.Batching.FlushInterval = d
				}
			}
		}
	}

	return resolved
}
