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

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeepCopyMapShallowFields(t *testing.T) {
	src := map[string]any{"url": "http://example.com", "port": 9200}
	cp := DeepCopyMap(src)

	assert.Equal(t, src, cp)

	// Mutate copy, original must be unchanged.
	cp["url"] = "http://changed.com"
	assert.Equal(t, "http://example.com", src["url"])
}

func TestDeepCopyMapNestedMap(t *testing.T) {
	src := map[string]any{
		"tls": map[string]any{"ca_file": "/old/ca.crt", "enabled": true},
	}
	cp := DeepCopyMap(src)

	// Mutate nested copy, original must be unchanged.
	nested := cp["tls"].(map[string]any)
	nested["ca_file"] = "/new/ca.crt"

	origNested := src["tls"].(map[string]any)
	assert.Equal(t, "/old/ca.crt", origNested["ca_file"], "deep copy must isolate nested maps")
}

func TestDeepCopyMapNil(t *testing.T) {
	assert.Nil(t, DeepCopyMap(nil))
}

func TestDeepCopyMapEmpty(t *testing.T) {
	cp := DeepCopyMap(map[string]any{})
	assert.NotNil(t, cp)
	assert.Empty(t, cp)
}
