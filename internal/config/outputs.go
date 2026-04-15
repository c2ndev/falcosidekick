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
	"os"

	"gopkg.in/yaml.v3"
)

// OutputsConfig holds output definitions loaded from one or more output files.
type OutputsConfig struct {
	Outputs map[string]map[string]any `yaml:"outputs"`
}

// LoadOutputs reads output configurations from one or more YAML files.
// Files are processed left-to-right; same output names deep-merge.
func LoadOutputs(paths []string) (*OutputsConfig, error) {
	merged := &OutputsConfig{
		Outputs: make(map[string]map[string]any),
	}

	for _, path := range paths {
		data, err := os.ReadFile(path) //nolint:gosec // user-provided config file path
		if err != nil {
			return nil, fmt.Errorf("read output config %q: %w", path, err)
		}

		var raw map[string]any
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("parse output config %q: %w", path, err)
		}

		for key := range raw {
			if key != "outputs" {
				return nil, fmt.Errorf("output config %q: unknown top-level key %q (only \"outputs\" is allowed)", path, key)
			}
		}

		var partial OutputsConfig
		if err := yaml.Unmarshal(data, &partial); err != nil {
			return nil, fmt.Errorf("parse output config %q: %w", path, err)
		}

		mergeOutputs(merged.Outputs, partial.Outputs)
	}

	return merged, nil
}

// mergeOutputs deep-merges src output configs into dst by output name.
func mergeOutputs(dst, src map[string]map[string]any) {
	for name, srcCfg := range src {
		dstCfg, exists := dst[name]
		if !exists {
			dst[name] = srcCfg
			continue
		}
		deepMerge(dstCfg, srcCfg)
	}
}

// deepMerge recursively merges src into dst. Maps recurse; scalars overwrite.
func deepMerge(dst, src map[string]any) {
	for key, srcVal := range src {
		dstVal, exists := dst[key]
		if !exists {
			dst[key] = srcVal
			continue
		}

		srcMap, srcOK := srcVal.(map[string]any)
		dstMap, dstOK := dstVal.(map[string]any)
		if srcOK && dstOK {
			deepMerge(dstMap, srcMap)
		} else {
			dst[key] = srcVal
		}
	}
}
