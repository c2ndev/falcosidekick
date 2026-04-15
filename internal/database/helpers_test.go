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

package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeepCopyMapFlat(t *testing.T) {
	original := map[string]any{"key": "value", "num": 42}
	cp := deepCopyMap(original)
	original["key"] = "changed"
	assert.Equal(t, "value", cp["key"])
}

func TestDeepCopyMapNested(t *testing.T) {
	original := map[string]any{
		"nested": map[string]any{"inner": "original"},
	}
	cp := deepCopyMap(original)
	original["nested"].(map[string]any)["inner"] = "mutated"
	assert.Equal(t, "original", cp["nested"].(map[string]any)["inner"])
}

func TestDeepCopyMapEmpty(t *testing.T) {
	cp := deepCopyMap(map[string]any{})
	assert.Empty(t, cp)
}
