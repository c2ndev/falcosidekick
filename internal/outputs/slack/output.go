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

package slack

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"text/template"

	"github.com/mitchellh/mapstructure"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/outputs/sdk"
)

const (
	defaultFooter = "https://github.com/falcosecurity/falcosidekick"
	formatAll     = "all"
	formatFields  = "fields"
	formatText    = "text"
)

type config struct {
	WebhookURL     string `mapstructure:"webhook_url"`
	Channel        string `mapstructure:"channel"`
	Footer         string `mapstructure:"footer"`
	IconURL        string `mapstructure:"icon_url"`
	IconEmoji      string `mapstructure:"icon_emoji"`
	Username       string `mapstructure:"username"`
	OutputFormat   string `mapstructure:"output_format"`
	MessageFormat  string `mapstructure:"message_format"`
	sdk.HTTPConfig `mapstructure:",squash"`
}

// Type describes the Slack output for the catalog.
var Type = domain.OutputType{
	New:      createOutput,
	Name:     "slack",
	Category: "chat",
	Schema: domain.OutputSchema{
		Fields: append([]domain.SchemaField{
			{Name: "webhook_url", Type: "string", Required: true, Label: "Webhook URL", Secret: true},
			{Name: "channel", Type: "string", Label: "Channel"},
			{Name: "username", Type: "string", Label: "Bot Username"},
			{Name: "icon_url", Type: "string", Label: "Icon URL"},
			{Name: "icon_emoji", Type: "string", Label: "Icon Emoji (e.g., :ghost:)"},
			{Name: "output_format", Type: "enum", Values: []string{"all", "fields", "text"}, Default: "all", Label: "Output Format"},
			{Name: "message_format", Type: "string", Label: "Message Template"},
			{Name: "footer", Type: "string", Label: "Footer"},
		}, sdk.HTTPConfigSchemaFields()...),
	},
}

type output struct {
	sender      *sdk.Sender
	logger      *slog.Logger
	messageTmpl *template.Template
	cfg         config
}

func createOutput(raw map[string]any, deps domain.OutputDeps) (domain.OutputDriver, error) {
	var cfg config
	if err := mapstructure.Decode(raw, &cfg); err != nil {
		return nil, fmt.Errorf("slack config: %w", err)
	}
	if cfg.WebhookURL == "" {
		return nil, fmt.Errorf("slack: webhook_url is required")
	}
	if cfg.OutputFormat == "" {
		cfg.OutputFormat = formatAll
	}
	if cfg.Footer == "" {
		cfg.Footer = defaultFooter
	}

	o := &output{
		cfg:    cfg,
		sender: sdk.NewSender("slack", &cfg.HTTPConfig),
		logger: sdk.ResolveLogger(deps.Logger, "slack"),
	}

	if cfg.MessageFormat != "" {
		tmpl, err := template.New("slack").Parse(cfg.MessageFormat)
		if err != nil {
			return nil, fmt.Errorf("slack: parse message template: %w", err)
		}
		o.messageTmpl = tmpl
	}

	return o, nil
}

func (o *output) Name() string { return "slack" }

func (o *output) Init(_ context.Context) error { return nil }

// Send delivers an event as a Slack attachment.
// Checks the response body because Slack returns HTTP 200 with error text on failure.
func (o *output) Send(ctx context.Context, event *domain.Event) error {
	return o.sender.SendJSONCheckBody(ctx, http.MethodPost, o.cfg.WebhookURL, o.buildPayload(event), checkSlackResponse)
}

// HealthCheck verifies connectivity to the Slack webhook.
func (o *output) HealthCheck(ctx context.Context) error {
	return o.sender.HealthCheck(ctx, o.cfg.WebhookURL)
}

func (o *output) Close() error { return nil }

// checkSlackResponse validates the Slack webhook response body.
// Slack returns HTTP 200 with body "ok" on success, or error text like
// "invalid_payload", "channel_not_found", "no_service" on failure.
func checkSlackResponse(body []byte) error {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || bytes.Equal(body, []byte("ok")) {
		return nil
	}
	return fmt.Errorf("slack: %s", string(body))
}
