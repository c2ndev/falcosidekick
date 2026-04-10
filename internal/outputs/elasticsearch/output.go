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

package elasticsearch

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/outputs/sdk"
)

const (
	defaultIndex  = "falco"
	defaultSuffix = "daily"
	suffixNone    = "none"
)

type config struct {
	URL                 string `mapstructure:"url"`
	Index               string `mapstructure:"index"`
	Suffix              string `mapstructure:"index_suffix"`
	Pipeline            string `mapstructure:"pipeline"`
	APIKey              string `mapstructure:"api_key"`
	sdk.HTTPConfig      `mapstructure:",squash"`
	NumberOfShards      int  `mapstructure:"number_of_shards"`
	NumberOfReplicas    int  `mapstructure:"number_of_replicas"`
	FlattenFields       bool `mapstructure:"flatten_fields"`
	CreateIndexTemplate bool `mapstructure:"create_index_template"`
}

// Type describes the Elasticsearch output for the catalog.
var Type = domain.OutputType{
	New:      createOutput,
	Name:     "elasticsearch",
	Category: "logs",
	Schema: domain.OutputSchema{
		Fields: append([]domain.SchemaField{
			{Name: "url", Type: "string", Required: true, Label: "URL"},
			{Name: "index", Type: "string", Default: "falco", Label: "Index"},
			{Name: "index_suffix", Type: "enum", Values: []string{"daily", "monthly", "annually", suffixNone}, Default: "daily", Label: "Index Suffix"},
			{Name: "pipeline", Type: "string", Label: "Ingest Pipeline"},
			{Name: "api_key", Type: "string", Secret: true, Label: "API Key (overrides basic auth)"},
			{Name: "flatten_fields", Type: "bool", Default: false, Label: "Flatten Fields"},
			{Name: "create_index_template", Type: "bool", Default: false, Label: "Create Index Template"},
			{Name: "number_of_shards", Type: "int", Default: 3, Label: "Number of Shards"},
			{Name: "number_of_replicas", Type: "int", Default: 3, Label: "Number of Replicas"},
		}, sdk.HTTPConfigSchemaFields()...),
	},
}

type output struct {
	sender *sdk.Sender
	logger *slog.Logger
	cfg    config
}

func createOutput(raw map[string]any, deps domain.OutputDeps) (domain.OutputDriver, error) {
	var cfg config
	if err := mapstructure.Decode(raw, &cfg); err != nil {
		return nil, fmt.Errorf("elasticsearch config: %w", err)
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("elasticsearch: url is required")
	}
	if cfg.Index == "" {
		cfg.Index = defaultIndex
	}
	if cfg.Suffix == "" {
		cfg.Suffix = defaultSuffix
	}

	sender := sdk.NewSender("elasticsearch", &cfg.HTTPConfig)
	if cfg.APIKey != "" {
		sender.SetHeader("Authorization", "ApiKey "+cfg.APIKey)
	}

	return &output{
		sender: sender,
		logger: sdk.ResolveLogger(deps.Logger, "elasticsearch"),
		cfg:    cfg,
	}, nil
}

func (o *output) Name() string { return "elasticsearch" }

// Init creates the index template if configured.
func (o *output) Init(ctx context.Context) error {
	if o.cfg.CreateIndexTemplate {
		return o.createIndexTemplate(ctx)
	}
	return nil
}

// Send delivers a single event to Elasticsearch using the _doc API.
func (o *output) Send(ctx context.Context, event *domain.Event) error {
	body, err := o.marshalEvent(event)
	if err != nil {
		return fmt.Errorf("elasticsearch marshal: %w", err)
	}

	url := fmt.Sprintf("%s/%s/_doc", o.cfg.URL, o.resolveIndex())
	if o.cfg.Pipeline != "" {
		url += "?pipeline=" + o.cfg.Pipeline
	}

	return o.sender.SendRaw(ctx, http.MethodPost, url, body, "application/json")
}

// SendBatch delivers multiple events using the Elasticsearch bulk API.
// Uses "create" action (append-only, required for data streams).
// Parses per-item response to report accurate success/failure counts.
func (o *output) SendBatch(ctx context.Context, events []*domain.Event) error {
	body, err := o.buildBulkBody(events)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/_bulk?filter_path=%s", o.cfg.URL, bulkFilterPath)
	if o.cfg.Pipeline != "" {
		url += "&pipeline=" + o.cfg.Pipeline
	}

	respBody, err := o.sender.SendRawReadBody(ctx, http.MethodPost, url, body, "application/json")
	if err != nil {
		return err
	}

	return o.parseBulkResponse(respBody, len(events))
}

// HealthCheck verifies connectivity to Elasticsearch.
func (o *output) HealthCheck(ctx context.Context) error {
	return o.sender.HealthCheck(ctx, o.cfg.URL)
}

func (o *output) Close() error { return nil }

func (o *output) marshalEvent(event *domain.Event) ([]byte, error) {
	fields := event.OutputFields
	if o.cfg.FlattenFields {
		fields = make(map[string]interface{}, len(event.OutputFields))
		for k, v := range event.OutputFields {
			fields[strings.ReplaceAll(k, ".", "_")] = v
		}
	}

	type alias domain.Event
	tmp := struct {
		*alias
		OutputFields map[string]interface{} `json:"output_fields"`
		Timestamp    string                 `json:"@timestamp"`
	}{
		alias:        (*alias)(event),
		OutputFields: fields,
		Timestamp:    event.Time.Format(time.RFC3339Nano),
	}

	return json.Marshal(tmp)
}

func (o *output) resolveIndex() string {
	switch o.cfg.Suffix {
	case "monthly":
		return fmt.Sprintf("%s-%s", o.cfg.Index, time.Now().Format("2006.01"))
	case "annually":
		return fmt.Sprintf("%s-%s", o.cfg.Index, time.Now().Format("2006"))
	case suffixNone:
		return o.cfg.Index
	default:
		return fmt.Sprintf("%s-%s", o.cfg.Index, time.Now().Format("2006.01.02"))
	}
}
