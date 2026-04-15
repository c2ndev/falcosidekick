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

package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid https", "https://example.com", false},
		{"valid http with port", "http://localhost:9200", false},
		{"valid with path", "http://host:9200/api", false},
		{"empty", "", true},
		{"no scheme", "example.com", true},
		{"no host", "http://", true},
		{"relative path", "/api/v1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := ValidateURL(tt.url)
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		ep      string
		wantErr bool
	}{
		{"valid path", "/api/v1", false},
		{"valid with dots", "/api/v2/alerts", false},
		{"root", "/", false},
		{"empty allowed", "", false},
		{"no leading slash", "api/v1", true},
		{"spaces", "/api v1", true},
		{"backslash", "/api\\v1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := ValidateEndpoint(tt.ep)
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestValidateHosts(t *testing.T) {
	tests := []struct {
		name    string
		hosts   []string
		wantErr bool
	}{
		{"single valid", []string{"http://host:9093"}, false},
		{"multiple valid", []string{"http://a:9093", "http://b:9093"}, false},
		{"nil", nil, true},
		{"empty slice", []string{}, true},
		{"empty string entry", []string{""}, true},
		{"missing scheme", []string{"no-scheme"}, true},
		{"missing host", []string{"http://"}, true},
		{"mixed valid and empty", []string{"http://valid:9093", ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := ValidateHosts(tt.hosts)
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}
