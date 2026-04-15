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

	"github.com/mitchellh/mapstructure"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// PipelineConfig holds event pipeline settings.
type PipelineConfig struct {
	Outputs       map[string]map[string]any `mapstructure:"outputs"`
	output.Config `mapstructure:",squash"`
	Enricher      output.EnricherConfig `mapstructure:"enricher"`
}

// Validate checks the pipeline configuration for errors.
func (c *PipelineConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors

	errs.Merge("enricher", c.Enricher.Validate())
	errs.Merge("", c.Config.Validate())

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ResolveOutputConfig deep-merges pipeline defaults with per-output overrides.
// Only fields present in the per-output config override defaults.
func (c *PipelineConfig) ResolveOutputConfig(name string) (output.Config, error) {
	resolved := c.deepCopyDefaults()

	raw, ok := c.Outputs[name]
	if !ok {
		return resolved, nil
	}

	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook:       mapstructure.StringToTimeDurationHookFunc(),
		WeaklyTypedInput: true,
		Result:           &resolved,
	})
	if err != nil {
		return resolved, err
	}
	if err := dec.Decode(raw); err != nil {
		return resolved, err
	}

	if resolved.MinPriority != "" {
		if _, err := event.ParsePriority(string(resolved.MinPriority)); err != nil {
			return resolved, fmt.Errorf("output %q: %w", name, err)
		}
	}

	if errs := resolved.Validate(); len(errs) > 0 {
		return resolved, fmt.Errorf("output %q: %s", name, errs.Error())
	}

	return resolved, nil
}

// deepCopyDefaults returns a deep copy of the pipeline defaults so decoding.
func (c *PipelineConfig) deepCopyDefaults() output.Config {
	cp := c.Config
	if c.Config.Retry != nil {
		r := *c.Config.Retry
		cp.Retry = &r
	}
	if c.Config.CircuitBreaker != nil {
		cb := *c.Config.CircuitBreaker
		cp.CircuitBreaker = &cb
	}
	if c.Config.Batching != nil {
		b := *c.Config.Batching
		cp.Batching = &b
	}
	return cp
}
