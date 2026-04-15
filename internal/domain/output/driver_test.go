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

package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchQueryNormalize(t *testing.T) {
	tests := []struct {
		name      string
		wantSort  string
		query     SearchQuery
		wantLimit int
		wantPage  int
		wantErr   bool
	}{
		{
			name:      "defaults applied",
			query:     SearchQuery{},
			wantLimit: 100, wantPage: 1, wantSort: "timestamp",
		},
		{
			name:      "zero limit defaults to 100",
			query:     SearchQuery{Limit: 0},
			wantLimit: 100, wantPage: 1, wantSort: "timestamp",
		},
		{
			name:      "negative limit defaults to 100",
			query:     SearchQuery{Limit: -5},
			wantLimit: 100, wantPage: 1, wantSort: "timestamp",
		},
		{
			name:      "limit capped at 1000",
			query:     SearchQuery{Limit: 5000},
			wantLimit: 1000, wantPage: 1, wantSort: "timestamp",
		},
		{
			name:      "negative page defaults to 1",
			query:     SearchQuery{Page: -1},
			wantLimit: 100, wantPage: 1, wantSort: "timestamp",
		},
		{
			name:      "valid sort by priority",
			query:     SearchQuery{SortBy: "priority"},
			wantLimit: 100, wantPage: 1, wantSort: "priority",
		},
		{
			name:      "valid sort by rule",
			query:     SearchQuery{SortBy: "rule"},
			wantLimit: 100, wantPage: 1, wantSort: "rule",
		},
		{
			name:    "invalid sort field",
			query:   SearchQuery{SortBy: "invalid_field"},
			wantErr: true,
		},
		{
			name:      "preserves valid values",
			query:     SearchQuery{Limit: 50, Page: 3, SortBy: "source"},
			wantLimit: 50, wantPage: 3, wantSort: "source",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.query.Normalize()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantLimit, tt.query.Limit)
			assert.Equal(t, tt.wantPage, tt.query.Page)
			assert.Equal(t, tt.wantSort, tt.query.SortBy)
		})
	}
}

func TestValidateGroupBy(t *testing.T) {
	tests := []struct {
		field   string
		wantErr bool
	}{
		{"priority", false},
		{"rule", false},
		{"source", false},
		{"tags", false},
		{"hostname", false},
		{"invalid", true},
		{"", true},
		{"uuid", true},
		{"output", true},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			err := ValidateGroupBy(tt.field)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
