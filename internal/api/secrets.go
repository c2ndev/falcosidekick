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

package api

import (
	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// SecretMask is the sentinel string substituted for secret field values
// in API responses. The UI renders it as a disabled input plus an explicit
// edit affordance; it must never be sent back as a new value.
const SecretMask = "****"

// maskOutputConfig returns a copy with fields flagged Secret in the
// schema replaced by SecretMask. When t.Name == "" every string value
// is masked as a conservative fallback.
func maskOutputConfig(entry core.OutputConfigEntry, t output.Type) core.OutputConfigEntry {
	entry.Config = utils.DeepCopyMap(entry.Config)
	if entry.Config == nil {
		return entry
	}

	if t.Name == "" {
		for k, v := range entry.Config {
			if _, ok := v.(string); ok {
				entry.Config[k] = SecretMask
			}
		}
		return entry
	}

	for _, f := range t.Schema.Fields {
		if !f.Secret {
			continue
		}
		if _, ok := entry.Config[f.Name]; ok {
			entry.Config[f.Name] = SecretMask
		}
	}
	return entry
}

func maskOutputConfigs(entries map[string]core.OutputConfigEntry, cat *catalog.Catalog) map[string]core.OutputConfigEntry {
	if entries == nil {
		return nil
	}
	result := make(map[string]core.OutputConfigEntry, len(entries))
	for name, entry := range entries {
		t, _ := cat.Get(name)
		result[name] = maskOutputConfig(entry, t)
	}
	return result
}

func maskCoreConfig(cfg *core.Config) *core.Config {
	if cfg == nil {
		return nil
	}
	return cfg.DeepCopy()
}
