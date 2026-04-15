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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sidekick.yaml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func writeTestOutputs(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "outputs.yaml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestRunStringSliceFlag(t *testing.T) {
	var f stringSliceFlag
	require.NoError(t, f.Set("a"))
	require.NoError(t, f.Set("b"))
	assert.Equal(t, "a,b", f.String())
	assert.Len(t, f, 2)
}

func TestRunInvalidConfigPath(t *testing.T) {
	err := run("/nonexistent/config.yaml", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config load")
}

func TestRunInvalidOutputPath(t *testing.T) {
	cfg := writeTestConfig(t, "{}")
	err := run(cfg, []string{"/nonexistent/outputs.yaml"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outputs load")
}

func TestRunConfigValidationFailure(t *testing.T) {
	cfg := writeTestConfig(t, "listen_port: -1")
	err := run(cfg, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config validation")
}

func TestRunUnknownOutputType(t *testing.T) {
	cfg := writeTestConfig(t, "{}")
	outs := writeTestOutputs(t, `
outputs:
  nonexistent_output:
    url: "http://example.com"
`)
	err := run(cfg, []string{outs})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent_output")
}

func TestRunSecretResolutionFailure(t *testing.T) {
	cfg := writeTestConfig(t, "{}")
	outs := writeTestOutputs(t, `
outputs:
  webhook:
    url: "http://example.com"
    password_file: /nonexistent/secret
`)
	err := run(cfg, []string{outs})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret resolution")
}

func TestRunUnknownCoreConfigKey(t *testing.T) {
	cfg := writeTestConfig(t, "listen_portt: 3000")
	err := run(cfg, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen_portt")
}
