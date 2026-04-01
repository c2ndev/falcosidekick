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
	CustomFields           map[string]string
	TemplatedFields        map[string]string
	BracketReplacer        string
	CustomTags             []string
	TruncateEventThreshold int
	TruncateFieldThreshold int
}

// Enricher adds custom fields, tags, UUID, and applies transformations to events.
type Enricher struct {
	customFields           map[string]string
	templatedFields        map[string]*template.Template
	bracketReplacer        string
	customTags             []string
	truncateEventThreshold int
	truncateFieldThreshold int
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

	eventThreshold := cfg.TruncateEventThreshold
	if eventThreshold <= 0 {
		eventThreshold = defaultTruncateEventThreshold
	}
	fieldThreshold := cfg.TruncateFieldThreshold
	if fieldThreshold <= 0 {
		fieldThreshold = defaultTruncateFieldThreshold
	}

	return &Enricher{
		customFields:           cfg.CustomFields,
		customTags:             cfg.CustomTags,
		templatedFields:        templates,
		bracketReplacer:        cfg.BracketReplacer,
		truncateEventThreshold: eventThreshold,
		truncateFieldThreshold: fieldThreshold,
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
	for k, v := range e.customFields {
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
	if len(e.customTags) == 0 {
		return
	}
	event.Tags = append(event.Tags, e.customTags...)
	sort.Strings(event.Tags)
}

func (e *Enricher) applyDefaultHostname(event *domain.Event) {
	if event.Hostname == "" {
		event.Hostname = defaultHostname
	}
}

func (e *Enricher) replaceBrackets(event *domain.Event) {
	if e.bracketReplacer == "" {
		return
	}
	replacer := strings.NewReplacer("[", e.bracketReplacer, "]", e.bracketReplacer)
	replaced := make(map[string]interface{}, len(event.OutputFields))
	for k, v := range event.OutputFields {
		replaced[replacer.Replace(k)] = v
	}
	event.OutputFields = replaced
}

func (e *Enricher) truncateIfNeeded(event *domain.Event) {
	data, err := json.Marshal(event)
	if err != nil || len(data) <= e.truncateEventThreshold {
		return
	}
	for k, v := range event.OutputFields {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if len(s) > e.truncateFieldThreshold {
			event.OutputFields[k] = s[:e.truncateFieldThreshold-len(truncateFieldSuffix)] + truncateFieldSuffix
		}
	}
}
