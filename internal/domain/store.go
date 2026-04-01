package domain

import (
	"context"
	"fmt"
	"time"
)

// EventStore is the interface for event persistence and querying.
// Implementations can be in-memory, SQLite, PostgreSQL, or Redis.
type EventStore interface {
	Append(ctx context.Context, event Event) error
	Search(ctx context.Context, query SearchQuery) (*SearchResult, error)
	Count(ctx context.Context, filters Filters) (int64, error)
	CountBy(ctx context.Context, field string, filters Filters) (map[string]int64, error)
	Close() error
}

// SearchQuery defines parameters for querying stored events.
type SearchQuery struct {
	Filter   string  `json:"filter"`
	Filters  Filters `json:"filters"`
	SortBy   string  `json:"sort_by"`
	SortDesc bool    `json:"sort_desc"`
	Page     int     `json:"page"`
	Limit    int     `json:"limit"`
}

// Filters defines structured filter criteria for event queries.
type Filters struct {
	Priority []string      `json:"priority,omitempty"`
	Rule     []string      `json:"rule,omitempty"`
	Source   []string      `json:"source,omitempty"`
	Hostname []string      `json:"hostname,omitempty"`
	Tags     []string      `json:"tags,omitempty"`
	Since    time.Duration `json:"since,omitempty"`
}

// SearchResult contains a page of events and pagination metadata.
type SearchResult struct {
	Events []Event `json:"events"`
	Total  int64   `json:"total"`
	Page   int     `json:"page"`
	Limit  int     `json:"limit"`
}

// Normalize applies defaults and validates the search query.
func (q *SearchQuery) Normalize() error {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Limit > 1000 {
		q.Limit = 1000
	}
	if q.Page <= 0 {
		q.Page = 1
	}
	if q.SortBy == "" {
		q.SortBy = "timestamp"
	}
	if !validSortFields[q.SortBy] {
		return fmt.Errorf("search: invalid sort_by %q", q.SortBy)
	}
	return nil
}

var validSortFields = map[string]bool{
	"timestamp": true, "priority": true, "rule": true, "source": true,
}

// ValidateGroupBy checks if a field name is allowed for CountBy.
func ValidateGroupBy(field string) error {
	if !validGroupByFields[field] {
		return fmt.Errorf("invalid group_by field: %q (allowed: priority, rule, source, tags, hostname)", field)
	}
	return nil
}

var validGroupByFields = map[string]bool{
	"priority": true, "rule": true, "source": true, "tags": true, "hostname": true,
}
