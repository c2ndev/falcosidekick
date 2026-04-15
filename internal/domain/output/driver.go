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
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
)

// Driver represents the send implementation for one output type.
type Driver interface {
	Name() string
	Init(ctx context.Context) error
	Send(ctx context.Context, evt *event.Event) error
	HealthCheck(ctx context.Context) error
	RuntimeConfig() RuntimeConfig
	Close() error
}

// BatchSender is an optional interface for outputs that support batch delivery.
// The dispatcher checks for this at startup. Batching activates only when both
// the output implements BatchSender and batching is enabled in config.
type BatchSender interface {
	SendBatch(ctx context.Context, events []*event.Event) error
}

// ReadableStore is an optional interface for outputs that support event queries.
// The API layer uses this to serve the UI. Only outputs configured as the
// ui.backend need to implement it (e.g., memory, redis, postgres).
type ReadableStore interface {
	Search(ctx context.Context, query *SearchQuery) (*SearchResult, error)
	Count(ctx context.Context, filters *Filters) (int64, error)
	CountBy(ctx context.Context, field string, filters *Filters) (map[string]int64, error)
}

// Type describes an available output kind.
type Type struct {
	New      func(cfg map[string]any, deps Deps) (Driver, error) `json:"-"`
	Name     string                                              `json:"name"`
	Category string                                              `json:"category"`
	Schema   Schema                                              `json:"schema"`
}

// Deps holds shared dependencies injected into outputs at creation.
type Deps struct {
	Logger  *slog.Logger
	Metrics core.MetricsCollector
}

// Schema describes configuration fields for an output type.
type Schema struct {
	Fields []SchemaField `json:"fields"`
}

// SchemaField describes a single configuration parameter.
type SchemaField struct {
	Default  any      `json:"default,omitempty"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Label    string   `json:"label"`
	Values   []string `json:"values,omitempty"`
	Required bool     `json:"required"`
	Secret   bool     `json:"secret,omitempty"`
}

// SearchQuery holds parameters for querying stored events.
type SearchQuery struct {
	Filter   string  `json:"filter"`
	SortBy   string  `json:"sort_by"`
	Filters  Filters `json:"filters"`
	Page     int     `json:"page"`
	Limit    int     `json:"limit"`
	SortDesc bool    `json:"sort_desc"`
}

// Filters holds structured filter criteria for event queries.
type Filters struct {
	Priority []string      `json:"priority,omitempty"`
	Rule     []string      `json:"rule,omitempty"`
	Source   []string      `json:"source,omitempty"`
	Hostname []string      `json:"hostname,omitempty"`
	Tags     []string      `json:"tags,omitempty"`
	Since    time.Duration `json:"since,omitempty"`
}

// SearchResult holds a page of events with pagination metadata.
type SearchResult struct {
	Events []event.Event `json:"events"`
	Total  int64         `json:"total"`
	Page   int           `json:"page"`
	Limit  int           `json:"limit"`
}

// Normalize applies defaults and validates the query.
// Default sort is timestamp descending (newest first).
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
		q.SortDesc = true
	}
	if !validSortFields[q.SortBy] {
		return fmt.Errorf("search: invalid sort_by %q", q.SortBy)
	}
	return nil
}

var validSortFields = map[string]bool{
	"timestamp": true, "priority": true, "rule": true, "source": true,
}

// ValidateGroupBy checks if a field is allowed for CountBy aggregation.
func ValidateGroupBy(field string) error {
	if !validGroupByFields[field] {
		return fmt.Errorf("invalid group_by field: %q", field)
	}
	return nil
}

var validGroupByFields = map[string]bool{
	"priority": true, "rule": true, "source": true, "tags": true, "hostname": true,
}
