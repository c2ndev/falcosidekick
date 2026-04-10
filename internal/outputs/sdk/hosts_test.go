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

package sdk

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateHosts(t *testing.T) {
	tests := []struct {
		name    string
		hosts   []string
		wantErr bool
	}{
		{hosts: []string{"http://host:9093"}, name: "single valid", wantErr: false},
		{hosts: []string{"http://a:9093", "http://b:9093"}, name: "multiple valid", wantErr: false},
		{hosts: nil, name: "nil", wantErr: true},
		{hosts: []string{}, name: "empty slice", wantErr: true},
		{hosts: []string{""}, name: "empty string entry", wantErr: true},
		{hosts: []string{"no-scheme"}, name: "missing scheme", wantErr: true},
		{hosts: []string{"http://"}, name: "missing host", wantErr: true},
		{hosts: []string{"http://valid:9093", ""}, name: "mixed valid and empty", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHosts("test", tt.hosts)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
