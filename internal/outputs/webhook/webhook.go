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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mitchellh/mapstructure"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

const (
	defaultMethod  = "POST"
	defaultTimeout = 10 * time.Second
)

type config struct {
	CustomHeaders   map[string]string `mapstructure:"customheaders"`
	CheckCert       *bool             `mapstructure:"checkcert"`
	Address         string            `mapstructure:"address"`
	Method          string            `mapstructure:"method"`
	MinimumPriority string            `mapstructure:"minimumpriority"`
}

// Type describes the webhook output for the catalog.
var Type = domain.OutputType{
	New:      createOutput,
	Name:     "webhook",
	Category: "webhook",
	Schema: domain.OutputSchema{
		Fields: []domain.SchemaField{
			{Name: "address", Type: "string", Required: true, Label: "URL"},
			{Name: "method", Type: "enum", Values: []string{"POST", "PUT"}, Default: "POST", Label: "HTTP Method"},
			{Name: "customheaders", Type: "map", Label: "Custom Headers"},
			{Name: "minimumpriority", Type: "priority", Label: "Minimum Priority"},
			{Name: "checkcert", Type: "bool", Default: true, Label: "Verify TLS Certificate"},
		},
	},
}

type output struct {
	client *http.Client
	cfg    config
}

func createOutput(raw map[string]any, _ domain.OutputDeps) (domain.Output, error) {
	var cfg config
	if err := mapstructure.Decode(raw, &cfg); err != nil {
		return nil, fmt.Errorf("webhook config: %w", err)
	}
	if cfg.Address == "" {
		return nil, fmt.Errorf("webhook: address is required")
	}
	if cfg.Method == "" {
		cfg.Method = defaultMethod
	}

	checkCert := true
	if cfg.CheckCert != nil {
		checkCert = *cfg.CheckCert
	}

	return &output{
		cfg:    cfg,
		client: buildHTTPClient(checkCert),
	}, nil
}

// Name returns the output identifier.
func (o *output) Name() string { return "webhook" }

// Init establishes connections. Webhook has no init-time work.
func (o *output) Init(_ context.Context) error { return nil }

// Send delivers an event as JSON to the webhook address.
func (o *output) Send(ctx context.Context, event *domain.Event) error {
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, o.cfg.Method, o.cfg.Address, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range o.cfg.CustomHeaders {
		req.Header.Set(k, v)
	}

	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook send: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= http.StatusBadRequest {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook: HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// HealthCheck verifies connectivity to the webhook address.
func (o *output) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, o.cfg.Address, http.NoBody)
	if err != nil {
		return fmt.Errorf("webhook healthcheck: %w", err)
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook healthcheck: %w", err)
	}
	_ = resp.Body.Close()
	return nil
}

// Close releases resources. Webhook has no persistent connections.
func (o *output) Close() error { return nil }

func buildHTTPClient(checkCert bool) *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !checkCert, //nolint:gosec // user-configurable TLS verification
			},
			MaxIdleConns:    10,
			IdleConnTimeout: 30 * time.Second,
		},
	}
}
