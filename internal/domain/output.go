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

package domain

import "context"

// OutputDriver represents the send implementation for one output type.
type OutputDriver interface {
	Name() string
	Init(ctx context.Context) error
	Send(ctx context.Context, event *Event) error
	HealthCheck(ctx context.Context) error
	Close() error
}

// OutputType describes an available output kind.
type OutputType struct {
	New      func(cfg map[string]any, deps OutputDeps) (OutputDriver, error) `json:"-"`
	Name     string                                                    `json:"name"`
	Category string                                                    `json:"category"`
	Schema   OutputSchema                                              `json:"schema"`
}

// OutputDeps holds shared dependencies injected into outputs at creation.
type OutputDeps struct {
	Metrics MetricsCollector
}

// OutputSchema describes configuration fields for an output type.
type OutputSchema struct {
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
