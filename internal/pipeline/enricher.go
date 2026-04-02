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

package pipeline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"github.com/google/uuid"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

const (
	defaultTruncateEventThreshold = 4096
	defaultTruncateFieldThreshold = 512
	truncateFieldSuffix           = "[...]"
	defaultHostname               = "unknown"
)

// EnricherConfig holds enrichment settings.
type EnricherConfig struct {
	CustomFields           map[string]string `mapstructure:"customfields"`
	TemplatedFields        map[string]string `mapstructure:"templatedfields"`
	BracketReplacer        string            `mapstructure:"bracketreplacer"`
	CustomTags             []string          `mapstructure:"customtags"`
	TruncateEventThreshold int               `mapstructure:"truncate_event_threshold"`
	TruncateFieldThreshold int               `mapstructure:"truncate_field_threshold"`
}

// Enricher adds custom fields, tags, UUID, and applies transformations to events.
type Enricher struct {
	templatedFields map[string]*template.Template
	cfg             EnricherConfig
}

// NewEnricher creates an Enricher from configuration.
func NewEnricher(cfg EnricherConfig) (*Enricher, error) {
	templates := make(map[string]*template.Template, len(cfg.TemplatedFields))
	for k, v := range cfg.TemplatedFields {
		tmpl, err := template.New(k).Parse(v)
		if err != nil {
			return nil, fmt.Errorf("enricher: parse template %q: %w", k, err)
		}
		templates[k] = tmpl
	}

	if cfg.TruncateEventThreshold <= 0 {
		cfg.TruncateEventThreshold = defaultTruncateEventThreshold
	}
	if cfg.TruncateFieldThreshold <= 0 {
		cfg.TruncateFieldThreshold = defaultTruncateFieldThreshold
	}
	if cfg.TruncateFieldThreshold <= len(truncateFieldSuffix) {
		return nil, fmt.Errorf("enricher: truncate_field_threshold must be > %d", len(truncateFieldSuffix))
	}

	return &Enricher{
		cfg:             cfg,
		templatedFields: templates,
	}, nil
}

// Enrich applies all enrichment steps to the event in place.
func (e *Enricher) Enrich(event *domain.Event) error {
	event.UUID = uuid.NewString()

	e.injectCustomFields(event)
	e.evaluateTemplatedFields(event)
	e.injectCustomTags(event)
	e.applyDefaultHostname(event)
	e.replaceBrackets(event)
	e.truncateIfNeeded(event)

	return nil
}

func (e *Enricher) injectCustomFields(event *domain.Event) {
	for k, v := range e.cfg.CustomFields {
		event.OutputFields[k] = v
	}
}

func (e *Enricher) evaluateTemplatedFields(event *domain.Event) {
	for k, tmpl := range e.templatedFields {
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, event.OutputFields); err != nil {
			continue
		}
		event.OutputFields[k] = buf.String()
	}
}

func (e *Enricher) injectCustomTags(event *domain.Event) {
	if len(e.cfg.CustomTags) == 0 {
		return
	}
	event.Tags = append(event.Tags, e.cfg.CustomTags...)
	sort.Strings(event.Tags)
}

func (e *Enricher) applyDefaultHostname(event *domain.Event) {
	if event.Hostname == "" {
		event.Hostname = defaultHostname
	}
}

func (e *Enricher) replaceBrackets(event *domain.Event) {
	if e.cfg.BracketReplacer == "" {
		return
	}
	replacer := strings.NewReplacer("[", e.cfg.BracketReplacer, "]", e.cfg.BracketReplacer)
	replaced := make(map[string]interface{}, len(event.OutputFields))
	for k, v := range event.OutputFields {
		replaced[replacer.Replace(k)] = v
	}
	event.OutputFields = replaced
}

func (e *Enricher) truncateIfNeeded(event *domain.Event) {
	data, err := json.Marshal(event)
	if err != nil || len(data) <= e.cfg.TruncateEventThreshold {
		return
	}
	for k, v := range event.OutputFields {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if len(s) > e.cfg.TruncateFieldThreshold {
			event.OutputFields[k] = s[:e.cfg.TruncateFieldThreshold-len(truncateFieldSuffix)] + truncateFieldSuffix
		}
	}
}
