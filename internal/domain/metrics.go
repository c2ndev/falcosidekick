package domain

import (
	"context"
	"time"
)

// MetricsCollector is the interface for unified observability.
// A single implementation records to both Prometheus and OTLP.
type MetricsCollector interface {
	RecordInput(ctx context.Context, source string, status string)
	RecordOutput(ctx context.Context, output string, status string, duration time.Duration)
	RecordDrop(ctx context.Context, output string)
	RecordError(ctx context.Context, component string, err error)
	RecordEvent(ctx context.Context, rule string, priority Priority, source string)
}
