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

package webhook

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/outputs/sdk"
)

const defaultMethod = "POST"

type config struct {
	URL            string `mapstructure:"url"`
	Method         string `mapstructure:"method"`
	sdk.HTTPConfig `mapstructure:",squash"`
}

// Type describes the webhook output for the catalog.
var Type = domain.OutputType{
	New:      createOutput,
	Name:     "webhook",
	Category: "webhook",
	Schema: domain.OutputSchema{
		Fields: append([]domain.SchemaField{
			{Name: "url", Type: "string", Required: true, Label: "URL"},
			{Name: "method", Type: "enum", Values: []string{"POST", "PUT"}, Default: "POST", Label: "HTTP Method"},
		}, sdk.HTTPConfigSchemaFields()...),
	},
}

type output struct {
	sender *sdk.Sender
	cfg    config
}

func createOutput(raw map[string]any, _ domain.OutputDeps) (domain.OutputDriver, error) {
	var cfg config
	if err := mapstructure.Decode(raw, &cfg); err != nil {
		return nil, fmt.Errorf("webhook config: %w", err)
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("webhook: url is required")
	}
	if cfg.Method == "" {
		cfg.Method = defaultMethod
	}

	return &output{
		cfg:    cfg,
		sender: sdk.NewSender("webhook", &cfg.HTTPConfig),
	}, nil
}

func (o *output) Name() string { return "webhook" }

func (o *output) Init(_ context.Context) error { return nil }

// Send delivers an event as JSON to the webhook address.
func (o *output) Send(ctx context.Context, event *domain.Event) error {
	return o.sender.SendJSON(ctx, o.cfg.Method, o.cfg.URL, event)
}

// HealthCheck verifies connectivity to the webhook address.
func (o *output) HealthCheck(ctx context.Context) error {
	return o.sender.HealthCheck(ctx, o.cfg.URL)
}

func (o *output) Close() error { return nil }
