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

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const defaultMethod = "POST"

type config struct {
	URL               string `mapstructure:"url"`
	Method            string `mapstructure:"method"`
	shared.HTTPConfig `mapstructure:",squash"`
	Runtime           output.RuntimeConfig `mapstructure:"runtime"`
}

// OutputType describes the webhook output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     "webhook",
	Category: "webhook",
	Schema: output.Schema{
		Fields: append([]output.SchemaField{
			{Name: "url", Type: "string", Required: true, Label: "URL"},
			{Name: "method", Type: "enum", Values: []string{"POST", "PUT"}, Default: "POST", Label: "HTTP Method"},
		}, append(shared.HTTPConfigSchemaFields(), shared.RuntimeConfigSchemaFields()...)...),
	},
}

type driver struct {
	sender *shared.Sender
	cfg    config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

var validMethods = map[string]bool{"POST": true, "PUT": true}

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.HTTPConfig.Validate())
	errs.Merge("url", shared.ValidateURL(c.URL))
	if c.Method == "" {
		c.Method = defaultMethod
	} else if !validMethods[c.Method] {
		errs.Add("method", fmt.Sprintf("must be POST or PUT, got %q", c.Method))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, _ output.Deps) (output.Driver, error) {
	var cfg config
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("webhook config: %w", err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("webhook: %s", errs.Error())
	}

	sender, err := shared.NewSender("webhook", &cfg.HTTPConfig)
	if err != nil {
		return nil, err
	}

	return &driver{
		cfg:    cfg,
		sender: sender,
	}, nil
}

func (d *driver) Name() string { return "webhook" }

func (d *driver) Init(_ context.Context) error { return nil }

// Send delivers an event as JSON to the webhook address.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	return d.sender.SendJSON(ctx, d.cfg.Method, d.cfg.URL, evt)
}

// HealthCheck verifies connectivity to the webhook address.
func (d *driver) HealthCheck(ctx context.Context) error {
	return d.sender.HealthCheck(ctx, d.cfg.URL)
}

func (d *driver) Close() error { return nil }
