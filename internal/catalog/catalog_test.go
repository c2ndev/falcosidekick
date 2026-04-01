package catalog

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

type stubOutput struct{ name string }

func (o *stubOutput) Name() string                                 { return o.name }
func (o *stubOutput) Init(_ context.Context) error                 { return nil }
func (o *stubOutput) Send(_ context.Context, _ domain.Event) error { return nil }
func (o *stubOutput) HealthCheck(_ context.Context) error          { return nil }
func (o *stubOutput) Close() error                                 { return nil }

func stubType(name, category string) domain.OutputType {
	return domain.OutputType{
		Name:     name,
		Category: category,
		Schema:   domain.OutputSchema{},
		New: func(_ map[string]any, _ domain.OutputDeps) (domain.Output, error) {
			return &stubOutput{name: name}, nil
		},
	}
}

func failingType(name string) domain.OutputType {
	return domain.OutputType{
		Name:     name,
		Category: "test",
		Schema:   domain.OutputSchema{},
		New: func(_ map[string]any, _ domain.OutputDeps) (domain.Output, error) {
			return nil, fmt.Errorf("constructor failed")
		},
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		types   []domain.OutputType
		wantErr bool
		errMsg  string
	}{
		{
			name:  "valid single type",
			types: []domain.OutputType{stubType("slack", "chat")},
		},
		{
			name:  "valid multiple types",
			types: []domain.OutputType{stubType("slack", "chat"), stubType("loki", "logs")},
		},
		{
			name:    "empty list",
			types:   []domain.OutputType{},
			wantErr: true,
			errMsg:  "at least one",
		},
		{
			name:    "nil list",
			types:   nil,
			wantErr: true,
			errMsg:  "at least one",
		},
		{
			name: "duplicate name",
			types: []domain.OutputType{
				stubType("slack", "chat"),
				stubType("slack", "chat"),
			},
			wantErr: true,
			errMsg:  "duplicate",
		},
		{
			name: "empty name",
			types: []domain.OutputType{
				{Name: "", Category: "test", New: func(_ map[string]any, _ domain.OutputDeps) (domain.Output, error) {
					return &stubOutput{}, nil
				}},
			},
			wantErr: true,
			errMsg:  "empty name",
		},
		{
			name: "nil constructor",
			types: []domain.OutputType{
				{Name: "broken", Category: "test", New: nil},
			},
			wantErr: true,
			errMsg:  "nil constructor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cat, err := New(tt.types)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, cat)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cat)
		})
	}
}

func TestGet(t *testing.T) {
	cat, err := New([]domain.OutputType{
		stubType("slack", "chat"),
		stubType("webhook", "webhook"),
	})
	require.NoError(t, err)

	tests := []struct {
		name  string
		found bool
	}{
		{"slack", true},
		{"webhook", true},
		{"nonexistent", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ot, ok := cat.Get(tt.name)
			assert.Equal(t, tt.found, ok)
			if tt.found {
				assert.Equal(t, tt.name, ot.Name)
			}
		})
	}
}

func TestAll(t *testing.T) {
	cat, err := New([]domain.OutputType{
		stubType("slack", "chat"),
		stubType("loki", "logs"),
		stubType("webhook", "webhook"),
	})
	require.NoError(t, err)

	all := cat.All()
	assert.Len(t, all, 3)

	names := make(map[string]bool)
	for _, t := range all {
		names[t.Name] = true
	}
	assert.True(t, names["slack"])
	assert.True(t, names["loki"])
	assert.True(t, names["webhook"])
}

func TestAllReturnsCopy(t *testing.T) {
	cat, err := New([]domain.OutputType{stubType("slack", "chat")})
	require.NoError(t, err)

	all := cat.All()
	all[0] = domain.OutputType{Name: "mutated"}

	original, ok := cat.Get("slack")
	assert.True(t, ok)
	assert.Equal(t, "slack", original.Name, "mutating All() result must not affect catalog")
}

func TestCreate(t *testing.T) {
	cat, err := New([]domain.OutputType{
		stubType("slack", "chat"),
		failingType("broken"),
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		output  string
		wantErr bool
		errMsg  string
	}{
		{"existing type", "slack", false, ""},
		{"unknown type", "nonexistent", true, "unknown"},
		{"failing constructor", "broken", true, "constructor failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := cat.Create(tt.output, nil, domain.OutputDeps{})
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.output, output.Name())
		})
	}
}

func TestNames(t *testing.T) {
	cat, err := New([]domain.OutputType{
		stubType("webhook", "webhook"),
		stubType("slack", "chat"),
	})
	require.NoError(t, err)

	names := cat.Names()
	assert.Len(t, names, 2)
	assert.Contains(t, names, "slack")
	assert.Contains(t, names, "webhook")
}
