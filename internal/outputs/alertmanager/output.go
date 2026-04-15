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

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// defaultEndpoint targets the Alertmanager v2 API.
const defaultEndpoint = "/api/v2/alerts"

type config struct {
	shared.HTTPConfig `mapstructure:",squash"`
	ExtraLabels       map[string]string `mapstructure:"extra_labels"`
	ExtraAnnotations  map[string]string `mapstructure:"extra_annotations"`
	CustomSeverityMap map[string]string `mapstructure:"custom_severity_map"`
	GeneratorURL      string            `mapstructure:"generator_url"`
	Endpoint          string            `mapstructure:"endpoint"`
	Hosts             []string          `mapstructure:"hosts"`
	ExpiresAfter      int               `mapstructure:"expires_after"`
}

// OutputType describes the Alertmanager output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     "alertmanager",
	Category: "alerting",
	Schema: output.Schema{
		Fields: append([]output.SchemaField{
			{Name: "hosts", Type: "string[]", Required: true, Label: "Hosts"},
			{Name: "endpoint", Type: "string", Default: defaultEndpoint, Label: "API Endpoint"},
			{Name: "generator_url", Type: "string", Label: "Generator URL (link back to source in AM UI)"},
			{Name: "expires_after", Type: "int", Default: 0, Label: "Alert Expires After (seconds, 0=never)"},
			{Name: "extra_labels", Type: "map", Label: "Extra Labels"},
			{Name: "extra_annotations", Type: "map", Label: "Extra Annotations"},
			{Name: "custom_severity_map", Type: "map", Label: "Custom Severity Map"},
		}, shared.HTTPConfigSchemaFields()...),
	},
}

type driver struct {
	sender   *shared.Sender
	logger   *slog.Logger
	hostURLs []string
	cfg      config
}

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.HTTPConfig.Validate())
	errs.Merge("hosts", shared.ValidateHosts(c.Hosts))
	errs.Merge("endpoint", shared.ValidateEndpoint(c.Endpoint))
	if c.Endpoint == "" {
		c.Endpoint = defaultEndpoint
	}
	if c.ExpiresAfter < 0 {
		errs.Add("expires_after", fmt.Sprintf("must be >= 0, got %d", c.ExpiresAfter))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, deps output.Deps) (output.Driver, error) {
	var cfg config
	if err := mapstructure.Decode(raw, &cfg); err != nil {
		return nil, fmt.Errorf("alertmanager config: %w", err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("alertmanager: %s", errs.Error())
	}

	hostURLs := make([]string, 0, len(cfg.Hosts))
	for _, host := range cfg.Hosts {
		hostURLs = append(hostURLs, host+cfg.Endpoint)
	}

	sender, err := shared.NewSender("alertmanager", &cfg.HTTPConfig)
	if err != nil {
		return nil, err
	}

	return &driver{
		cfg:      cfg,
		sender:   sender,
		logger:   shared.ResolveLogger(deps.Logger, "alertmanager"),
		hostURLs: hostURLs,
	}, nil
}

func (d *driver) Name() string { return "alertmanager" }

func (d *driver) Init(_ context.Context) error { return nil }

// Send delivers an event as an Alertmanager alert.
// Fan-out: sends to ALL configured hosts in parallel.
// Succeeds if at least one host accepts the alert.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	alerts := []alertPayload{d.buildAlert(evt)}

	body, err := json.Marshal(alerts)
	if err != nil {
		return fmt.Errorf("alertmanager marshal: %w", err)
	}

	if len(d.hostURLs) == 1 {
		return d.sender.SendRaw(ctx, http.MethodPost, d.hostURLs[0], body, "application/json")
	}

	return d.fanOut(ctx, body)
}

// fanOut sends to all hosts in parallel, succeeds if at least one works.
func (d *driver) fanOut(ctx context.Context, body []byte) error {
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		lastErr error
		success int
	)

	for _, url := range d.hostURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			if err := d.sender.SendRaw(ctx, http.MethodPost, url, body, "application/json"); err != nil {
				d.logger.Warn("host failed", "host", url, "error", err)
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
		return fmt.Errorf("alertmanager: all %d hosts failed: %w", len(d.hostURLs), lastErr)
	}

	failed := len(d.hostURLs) - success
	if failed > 0 {
		d.logger.Warn("partial fan-out", "succeeded", success, "failed", failed, "total", len(d.hostURLs))
	}

	return nil
}

// HealthCheck verifies connectivity to the first Alertmanager host.
func (d *driver) HealthCheck(ctx context.Context) error {
	if len(d.hostURLs) == 0 {
		return fmt.Errorf("alertmanager: no hosts configured")
	}
	base := strings.TrimSuffix(d.hostURLs[0], d.cfg.Endpoint)
	// TODO: consider checking all hosts.
	return d.sender.HealthCheck(ctx, base+"/-/healthy")
}

func (d *driver) Close() error { return nil }
