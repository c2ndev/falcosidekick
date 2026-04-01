package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchQueryNormalize(t *testing.T) {
	tests := []struct {
		name      string
		query     SearchQuery
		wantLimit int
		wantPage  int
		wantSort  string
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
