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

package alertmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/mitchellh/mapstructure"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/outputs/sdk"
)

// defaultEndpoint targets the Alertmanager v2 API.
const defaultEndpoint = "/api/v2/alerts"

type config struct {
	sdk.HTTPConfig    `mapstructure:",squash"`
	ExtraLabels       map[string]string `mapstructure:"extra_labels"`
	ExtraAnnotations  map[string]string `mapstructure:"extra_annotations"`
	CustomSeverityMap map[string]string `mapstructure:"custom_severity_map"`
	GeneratorURL      string            `mapstructure:"generator_url"`
	Endpoint          string            `mapstructure:"endpoint"`
	Hosts             []string          `mapstructure:"hosts"`
	ExpiresAfter      int               `mapstructure:"expires_after"`
}

// Type describes the Alertmanager output for the catalog.
var Type = domain.OutputType{
	New:      createOutput,
	Name:     "alertmanager",
	Category: "alerting",
	Schema: domain.OutputSchema{
		Fields: append([]domain.SchemaField{
			{Name: "hosts", Type: "string[]", Required: true, Label: "Hosts"},
			{Name: "endpoint", Type: "string", Default: defaultEndpoint, Label: "API Endpoint"},
			{Name: "generator_url", Type: "string", Label: "Generator URL (link back to source in AM UI)"},
			{Name: "expires_after", Type: "int", Default: 0, Label: "Alert Expires After (seconds, 0=never)"},
			{Name: "extra_labels", Type: "map", Label: "Extra Labels"},
			{Name: "extra_annotations", Type: "map", Label: "Extra Annotations"},
			{Name: "custom_severity_map", Type: "map", Label: "Custom Severity Map"},
		}, sdk.HTTPConfigSchemaFields()...),
	},
}

type output struct {
	sender   *sdk.Sender
	logger   *slog.Logger
	hostURLs []string
	cfg      config
}

func createOutput(raw map[string]any, deps domain.OutputDeps) (domain.OutputDriver, error) {
	var cfg config
	if err := mapstructure.Decode(raw, &cfg); err != nil {
		return nil, fmt.Errorf("alertmanager config: %w", err)
	}

	if err := sdk.ValidateHosts("alertmanager", cfg.Hosts); err != nil {
		return nil, err
	}

	if cfg.Endpoint == "" {
		cfg.Endpoint = defaultEndpoint
	}

	hostURLs := make([]string, 0, len(cfg.Hosts))
	for _, host := range cfg.Hosts {
		hostURLs = append(hostURLs, host+cfg.Endpoint)
	}

	return &output{
		cfg:      cfg,
		sender:   sdk.NewSender("alertmanager", &cfg.HTTPConfig),
		logger:   sdk.ResolveLogger(deps.Logger, "alertmanager"),
		hostURLs: hostURLs,
	}, nil
}

func (o *output) Name() string { return "alertmanager" }

func (o *output) Init(_ context.Context) error { return nil }

// Send delivers an event as an Alertmanager alert.
// Fan-out: sends to ALL configured hosts in parallel (Prometheus/Thanos pattern).
// Succeeds if at least one host accepts the alert.
func (o *output) Send(ctx context.Context, event *domain.Event) error {
	alerts := []alertPayload{o.buildAlert(event)}

	body, err := json.Marshal(alerts)
	if err != nil {
		return fmt.Errorf("alertmanager marshal: %w", err)
	}

	if len(o.hostURLs) == 1 {
		return o.sender.SendRaw(ctx, http.MethodPost, o.hostURLs[0], body, "application/json")
	}

	return o.fanOut(ctx, body)
}

// fanOut sends to all hosts in parallel, succeeds if at least one works.
func (o *output) fanOut(ctx context.Context, body []byte) error {
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		lastErr error
		success int
	)

	for _, url := range o.hostURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			if err := o.sender.SendRaw(ctx, http.MethodPost, url, body, "application/json"); err != nil {
				o.logger.Warn("host failed", "host", url, "error", err)
				mu.Lock()
				lastErr = err
				mu.Unlock()
				return
			}
			mu.Lock()
			success++
			mu.Unlock()
		}(url)
	}

	wg.Wait()

	if success == 0 {
		return fmt.Errorf("alertmanager: all %d hosts failed: %w", len(o.hostURLs), lastErr)
	}

	failed := len(o.hostURLs) - success
	if failed > 0 {
		o.logger.Warn("partial fan-out", "succeeded", success, "failed", failed, "total", len(o.hostURLs))
	}

	return nil
}

// HealthCheck verifies connectivity to the first Alertmanager host.
func (o *output) HealthCheck(ctx context.Context) error {
	if len(o.hostURLs) == 0 {
		return fmt.Errorf("alertmanager: no hosts configured")
	}
	base := strings.TrimSuffix(o.hostURLs[0], o.cfg.Endpoint)
	// TODO: consider checking all hosts.
	return o.sender.HealthCheck(ctx, base+"/-/healthy")
}

func (o *output) Close() error { return nil }
