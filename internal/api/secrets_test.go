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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func secretType(name string) output.Type {
	return output.Type{
		Name: name,
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return nil, assert.AnError
		},
		Schema: output.Schema{
			Fields: []output.SchemaField{
				{Name: "url", Type: "string"},
				{Name: "password", Type: "string", Secret: true},
				{Name: "token", Type: "string", Secret: true},
			},
		},
	}
}

func publicType(name string) output.Type {
	return output.Type{
		Name: name,
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return nil, assert.AnError
		},
		Schema: output.Schema{
			Fields: []output.SchemaField{
				{Name: "url", Type: "string"},
				{Name: "channel", Type: "string"},
			},
		},
	}
}

func TestMaskOutputConfig_NoSecretSchemaFields(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "slack",
		Config: map[string]any{
			"url":     "https://hooks.slack.com/x",
			"channel": "#alerts",
		},
		UpdatedAt: time.Now(),
	}

	masked := maskOutputConfig(entry, publicType("slack"))

	assert.Equal(t, "https://hooks.slack.com/x", masked.Config["url"])
	assert.Equal(t, "#alerts", masked.Config["channel"])
}

func TestMaskOutputConfig_SecretFieldPresent(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "elasticsearch",
		Config: map[string]any{
			"url":      "https://es:9200",
			"password": "hunter2",
		},
	}

	masked := maskOutputConfig(entry, secretType("elasticsearch"))

	assert.Equal(t, "https://es:9200", masked.Config["url"])
	assert.Equal(t, SecretMask, masked.Config["password"])
}

func TestMaskOutputConfig_SecretFieldAbsent(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "elasticsearch",
		Config: map[string]any{
			"url": "https://es:9200",
			// password intentionally omitted
		},
	}

	masked := maskOutputConfig(entry, secretType("elasticsearch"))

	_, hasPassword := masked.Config["password"]
	assert.False(t, hasPassword, "absent secret field must not be synthesized by the mask helper")
	assert.Equal(t, "https://es:9200", masked.Config["url"])
}

func TestMaskOutputConfig_MultipleSecretFields(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "elasticsearch",
		Config: map[string]any{
			"url":      "https://es:9200",
			"password": "p",
			"token":    "t",
		},
	}

	masked := maskOutputConfig(entry, secretType("elasticsearch"))

	assert.Equal(t, SecretMask, masked.Config["password"])
	assert.Equal(t, SecretMask, masked.Config["token"])
}

func TestMaskOutputConfig_UnknownType_MasksAllStrings(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "legacy",
		Config: map[string]any{
			"url":    "https://x",
			"port":   9200,
			"enable": true,
		},
	}

	masked := maskOutputConfig(entry, output.Type{})

	assert.Equal(t, SecretMask, masked.Config["url"], "string fields masked under unknown-type fallback")
	assert.Equal(t, 9200, masked.Config["port"], "non-string fields untouched")
	assert.Equal(t, true, masked.Config["enable"], "non-string fields untouched")
}

func TestMaskOutputConfig_CaseSensitiveMatch(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "weird",
		Config: map[string]any{
			"Password": "plaintext",
			"password": "secret",
		},
	}

	masked := maskOutputConfig(entry, secretType("weird"))

	assert.Equal(t, "plaintext", masked.Config["Password"], "uppercase Password does not match schema field password")
	assert.Equal(t, SecretMask, masked.Config["password"])
}

func TestMaskOutputConfig_DoesNotMutateInput(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "elasticsearch",
		Config: map[string]any{
			"password": "original",
			"url":      "https://es:9200",
		},
	}

	_ = maskOutputConfig(entry, secretType("elasticsearch"))

	assert.Equal(t, "original", entry.Config["password"], "original entry must not be mutated")
}

func TestMaskOutputConfig_NilConfig(t *testing.T) {
	entry := &core.OutputConfigEntry{Name: "x", Config: nil}

	masked := maskOutputConfig(entry, secretType("x"))

	assert.Nil(t, masked.Config)
}

func TestMaskOutputConfigs_LooksUpPerType(t *testing.T) {
	cat, err := catalog.New([]output.Type{secretType("elasticsearch"), publicType("slack")})
	require.NoError(t, err)

	entries := map[string]*core.OutputConfigEntry{
		"elasticsearch": {Name: "elasticsearch", Config: map[string]any{"password": "x", "url": "u"}},
		"slack":         {Name: "slack", Config: map[string]any{"url": "https://s", "channel": "#c"}},
		"unknown":       {Name: "unknown", Config: map[string]any{"token": "t", "port": 80}},
	}

	masked := maskOutputConfigs(entries, cat)

	assert.Equal(t, SecretMask, masked["elasticsearch"].Config["password"])
	assert.Equal(t, "u", masked["elasticsearch"].Config["url"])
	assert.Equal(t, "https://s", masked["slack"].Config["url"])
	assert.Equal(t, "#c", masked["slack"].Config["channel"])
	assert.Equal(t, SecretMask, masked["unknown"].Config["token"], "unknown type falls back to all-string mask")
	assert.Equal(t, 80, masked["unknown"].Config["port"])
}

func TestMaskOutputConfigs_NilInput(t *testing.T) {
	cat, err := catalog.New([]output.Type{publicType("slack")})
	require.NoError(t, err)

	assert.Nil(t, maskOutputConfigs(nil, cat))
}

func TestMaskCoreConfig_CopiesAndReturnsEquivalent(t *testing.T) {
	cfg := &core.Config{
		ListenAddress: "0.0.0.0",
		ListenPort:    2801,
		LogLevel:      core.LogLevelInfo,
		LogFormat:     core.LogFormatText,
	}

	masked := maskCoreConfig(cfg)

	require.NotNil(t, masked)
	assert.NotSame(t, cfg, masked, "masker must return a copy, not the same pointer")
	assert.Equal(t, cfg.ListenAddress, masked.ListenAddress)
	assert.Equal(t, cfg.ListenPort, masked.ListenPort)
}

func TestMaskCoreConfig_Nil(t *testing.T) {
	assert.Nil(t, maskCoreConfig(nil))
}

func nestedSecretType() output.Type {
	return output.Type{
		Name: "kafka",
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return nil, assert.AnError
		},
		Schema: output.Schema{
			Fields: []output.SchemaField{
				{Name: "topic", Type: "string"},
				{Name: "auth.sasl", Type: "string"},
				{Name: "auth.username", Type: "string"},
				{Name: "auth.password", Type: "string", Secret: true},
			},
		},
	}
}

func TestMaskOutputConfig_NestedSecretPath(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "kafka",
		Config: map[string]any{
			"topic": "falco-events",
			"auth": map[string]any{
				"sasl":     "plain",
				"username": "alice",
				"password": "real-password",
			},
		},
	}

	masked := maskOutputConfig(entry, nestedSecretType())

	auth := masked.Config["auth"].(map[string]any)
	assert.Equal(t, SecretMask, auth["password"], "nested auth.password must be masked")
	assert.Equal(t, "plain", auth["sasl"], "non-secret nested siblings must not be touched")
	assert.Equal(t, "alice", auth["username"])

	origAuth := entry.Config["auth"].(map[string]any)
	assert.Equal(t, "real-password", origAuth["password"], "original entry must not be mutated")
}

func TestMaskOutputConfig_NestedSecretPathAbsentParent(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name:   "kafka",
		Config: map[string]any{"topic": "t"},
	}
	masked := maskOutputConfig(entry, nestedSecretType())
	_, hasAuth := masked.Config["auth"]
	assert.False(t, hasAuth, "absent parent must not be synthesized by the masker")
}

func TestContainsSecretPlaceholder_NestedPath(t *testing.T) {
	cfg := map[string]any{
		"topic": "t",
		"auth": map[string]any{
			"username": "alice",
			"password": SecretMask,
		},
	}
	field := containsSecretPlaceholder(cfg, nestedSecretType())
	assert.Equal(t, "auth.password", field)
}

func TestContainsSecretPlaceholder_NestedPathAbsentIsSafe(t *testing.T) {
	cfg := map[string]any{
		"topic": "t",
		"auth":  map[string]any{"username": "alice"},
	}
	assert.Empty(t, containsSecretPlaceholder(cfg, nestedSecretType()),
		"absent nested secret is a valid keep-existing PUT; must not be rejected")
}
