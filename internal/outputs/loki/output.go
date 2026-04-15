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

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const defaultEndpoint = "/loki/api/v1/push"

type config struct {
	URL               string `mapstructure:"url"`
	Tenant            string `mapstructure:"tenant"`
	Endpoint          string `mapstructure:"endpoint"`
	LogFormat         string `mapstructure:"log_format"`
	ExtraLabels       string `mapstructure:"extra_labels"`
	shared.HTTPConfig `mapstructure:",squash"`
}

// OutputType describes the Loki output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     "loki",
	Category: "logs",
	Schema: output.Schema{
		Fields: append([]output.SchemaField{
			{Name: "url", Type: "string", Required: true, Label: "URL"},
			{Name: "tenant", Type: "string", Label: "Tenant (X-Scope-OrgID)"},
			{Name: "log_format", Type: "enum", Values: []string{"json", "text"}, Default: "json", Label: "Log Format"},
			{Name: "extra_labels", Type: "string", Label: "Extra Labels (comma-separated field names)"},
		}, shared.HTTPConfigSchemaFields()...),
	},
}

type driver struct {
	sender      *shared.Sender
	logger      *slog.Logger
	cfg         config
	extraLabels []string
}

var validLogFormats = map[string]bool{formatJSON: true, "text": true}

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.HTTPConfig.Validate())
	errs.Merge("url", shared.ValidateURL(c.URL))
	errs.Merge("endpoint", shared.ValidateEndpoint(c.Endpoint))
	if c.Endpoint == "" {
		c.Endpoint = defaultEndpoint
	}
	if c.LogFormat == "" {
		c.LogFormat = formatJSON
	} else if !validLogFormats[c.LogFormat] {
		errs.Add("log_format", fmt.Sprintf("must be json/text, got %q", c.LogFormat))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, deps output.Deps) (output.Driver, error) {
	var cfg config
	if err := mapstructure.Decode(raw, &cfg); err != nil {
		return nil, fmt.Errorf("loki config: %w", err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("loki: %s", errs.Error())
	}

	sender, err := shared.NewSender("loki", &cfg.HTTPConfig)
	if err != nil {
		return nil, err
	}
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

	return &driver{
		cfg:         cfg,
		sender:      sender,
		logger:      shared.ResolveLogger(deps.Logger, "loki"),
		extraLabels: extraLabels,
	}, nil
}

func (o *driver) Name() string { return "loki" }

func (o *driver) Init(_ context.Context) error { return nil }

// Send delivers a single event to Loki with gzip compression.
func (o *driver) Send(ctx context.Context, evt *event.Event) error {
	payload := buildPayload(o.cfg.LogFormat, o.extraLabels, evt)
	return o.sender.SendGzipJSON(ctx, http.MethodPost, o.pushURL(), payload)
}

// SendBatch delivers multiple events to Loki in a single push request.
// Events with identical label sets are grouped into the same stream.
// Entries within each stream are ordered by timestamp.
func (o *driver) SendBatch(ctx context.Context, events []*event.Event) error {
	payload := buildBatchPayload(o.cfg.LogFormat, o.extraLabels, events)
	return o.sender.SendGzipJSON(ctx, http.MethodPost, o.pushURL(), payload)
}

// HealthCheck verifies connectivity to Loki.
func (o *driver) HealthCheck(ctx context.Context) error {
	return o.sender.HealthCheck(ctx, o.cfg.URL+"/ready")
}

func (o *driver) Close() error { return nil }

func (o *driver) pushURL() string {
	return o.cfg.URL + o.cfg.Endpoint
}
