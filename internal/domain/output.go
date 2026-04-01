package domain

import "context"

// Output is a running, configured output instance that delivers events
// to an external system. Implementations must be safe for concurrent
// calls from multiple worker goroutines.
type Output interface {
	Name() string
	Init(ctx context.Context) error
	Send(ctx context.Context, event Event) error
	HealthCheck(ctx context.Context) error
	Close() error
}

// OutputType describes an available output kind. Each output package
// exports a Type variable with its metadata and constructor.
type OutputType struct {
	Name     string                                           `json:"name"`
	Category string                                           `json:"category"`
	Schema   OutputSchema                                     `json:"schema"`
	New      func(cfg map[string]any, deps OutputDeps) (Output, error) `json:"-"`
}

// OutputDeps provides shared dependencies injected into outputs at creation.
type OutputDeps struct {
	Metrics MetricsCollector
}

// OutputSchema describes the configuration fields for an output type.
// Used by the UI to generate dynamic configuration forms.
type OutputSchema struct {
	Fields []SchemaField `json:"fields"`
}

// SchemaField describes a single configuration parameter.
type SchemaField struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"` // string, int, bool, enum, priority, map, secret
	Required bool     `json:"required"`
	Label    string   `json:"label"`
	Default  any      `json:"default,omitempty"`
	Values   []string `json:"values,omitempty"` // for enum type
	Secret   bool     `json:"secret,omitempty"`
}
