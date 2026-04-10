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

package loki

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mitchellh/mapstructure"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/outputs/sdk"
)

const defaultEndpoint = "/loki/api/v1/push"

type config struct {
	URL            string `mapstructure:"url"`
	Tenant         string `mapstructure:"tenant"`
	Endpoint       string `mapstructure:"endpoint"`
	LogFormat      string `mapstructure:"log_format"`
	ExtraLabels    string `mapstructure:"extra_labels"`
	sdk.HTTPConfig `mapstructure:",squash"`
}

// Type describes the Loki output for the catalog.
var Type = domain.OutputType{
	New:      createOutput,
	Name:     "loki",
	Category: "logs",
	Schema: domain.OutputSchema{
		Fields: append([]domain.SchemaField{
			{Name: "url", Type: "string", Required: true, Label: "URL"},
			{Name: "tenant", Type: "string", Label: "Tenant (X-Scope-OrgID)"},
			{Name: "log_format", Type: "enum", Values: []string{"json", "text"}, Default: "json", Label: "Log Format"},
			{Name: "extra_labels", Type: "string", Label: "Extra Labels (comma-separated field names)"},
		}, sdk.HTTPConfigSchemaFields()...),
	},
}

type output struct {
	sender      *sdk.Sender
	logger      *slog.Logger
	cfg         config
	extraLabels []string
}

func createOutput(raw map[string]any, deps domain.OutputDeps) (domain.OutputDriver, error) {
	var cfg config
	if err := mapstructure.Decode(raw, &cfg); err != nil {
		return nil, fmt.Errorf("loki config: %w", err)
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("loki: url is required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = defaultEndpoint
	}
	if cfg.LogFormat == "" {
		cfg.LogFormat = formatJSON
	}

	sender := sdk.NewSender("loki", &cfg.HTTPConfig)
	if cfg.Tenant != "" {
		sender.SetHeader("X-Scope-OrgID", cfg.Tenant)
	}

	var extraLabels []string
	if cfg.ExtraLabels != "" {
		for _, l := range strings.Split(cfg.ExtraLabels, ",") {
			l = strings.TrimSpace(l)
			if l != "" {
				extraLabels = append(extraLabels, l)
			}
		}
	}

	return &output{
		cfg:         cfg,
		sender:      sender,
		logger:      sdk.ResolveLogger(deps.Logger, "loki"),
		extraLabels: extraLabels,
	}, nil
}

func (o *output) Name() string { return "loki" }

func (o *output) Init(_ context.Context) error { return nil }

// Send delivers a single event to Loki with gzip compression.
func (o *output) Send(ctx context.Context, event *domain.Event) error {
	payload := buildPayload(o.cfg.LogFormat, o.extraLabels, event)
	return o.sender.SendGzipJSON(ctx, http.MethodPost, o.pushURL(), payload)
}

// SendBatch delivers multiple events to Loki in a single push request.
// Events with identical label sets are grouped into the same stream.
// Entries within each stream are ordered by timestamp.
func (o *output) SendBatch(ctx context.Context, events []*domain.Event) error {
	payload := buildBatchPayload(o.cfg.LogFormat, o.extraLabels, events)
	return o.sender.SendGzipJSON(ctx, http.MethodPost, o.pushURL(), payload)
}

// HealthCheck verifies connectivity to Loki.
func (o *output) HealthCheck(ctx context.Context) error {
	return o.sender.HealthCheck(ctx, o.cfg.URL+"/ready")
}

func (o *output) Close() error { return nil }

func (o *output) pushURL() string {
	return o.cfg.URL + o.cfg.Endpoint
}
