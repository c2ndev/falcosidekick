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
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/outputs/sdk"
)

// alertPayload matches the Alertmanager v2 API POST /api/v2/alerts schema.
// Fields match the OpenAPI spec: labels (required), annotations, startsAt, endsAt, generatorURL.
type alertPayload struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	StartsAt     string            `json:"startsAt,omitempty"`
	EndsAt       string            `json:"endsAt,omitempty"`
	GeneratorURL string            `json:"generatorURL,omitempty"`
}

func (o *output) buildAlert(event *domain.Event) alertPayload {
	labels := map[string]string{
		"alertname": sdk.SanitizeLabel(event.Rule),
		"source":    event.Source,
		"rule":      sdk.SanitizeLabel(event.Rule),
		"priority":  string(event.Priority),
		"severity":  o.resolveSeverity(event.Priority),
	}

	if event.Hostname != "" {
		labels["hostname"] = event.Hostname
	}

	if tags := sdk.FormatTags(event.Tags, ","); tags != "" {
		labels["tags"] = tags
	}

	for k, v := range o.cfg.ExtraLabels {
		labels[sdk.SanitizeLabel(k)] = sdk.SanitizeLabel(v)
	}

	annotations := map[string]string{
		"info":        event.Output,
		"description": event.Output,
		"summary":     event.Rule,
	}
	for k, v := range o.cfg.ExtraAnnotations {
		annotations[k] = v
	}

	alert := alertPayload{
		Labels:      labels,
		Annotations: annotations,
		StartsAt:    event.Time.UTC().Format(time.RFC3339),
	}

	if o.cfg.GeneratorURL != "" {
		alert.GeneratorURL = o.cfg.GeneratorURL
	}

	if o.cfg.ExpiresAfter > 0 {
		alert.EndsAt = event.Time.Add(time.Duration(o.cfg.ExpiresAfter) * time.Second).UTC().Format(time.RFC3339)
	}

	return alert
}

func (o *output) resolveSeverity(priority domain.Priority) string {
	p := strings.ToLower(string(priority))
	if o.cfg.CustomSeverityMap != nil {
		if s, ok := o.cfg.CustomSeverityMap[p]; ok {
			return s
		}
	}
	return sdk.PrioritySeverity(priority)
}
