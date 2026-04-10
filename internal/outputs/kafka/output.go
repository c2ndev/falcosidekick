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

package kafka

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/mitchellh/mapstructure"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/outputs/sdk"
)

type config struct {
	sdk.TLSConfig   `mapstructure:",squash"`
	ClientID        string   `mapstructure:"client_id"`
	Topic           string   `mapstructure:"topic"`
	TopicField      string   `mapstructure:"topic_field"`
	MessageKey      string   `mapstructure:"message_key"`
	MessageKeyField string   `mapstructure:"message_key_field"`
	SASL            string   `mapstructure:"sasl"`
	Username        string   `mapstructure:"username"`
	Password        string   `mapstructure:"password"`
	Compression     string   `mapstructure:"compression"`
	Balancer        string   `mapstructure:"balancer"`
	RequiredACKs    string   `mapstructure:"required_acks"`
	Brokers         []string `mapstructure:"brokers"`
	TLSEnabled      bool     `mapstructure:"tls_enabled"`
	Async           bool     `mapstructure:"async"`
	TopicCreation   bool     `mapstructure:"auto_create_topic"`
}

// Type describes the Kafka output for the catalog.
var Type = domain.OutputType{
	New:      createOutput,
	Name:     "kafka",
	Category: "queue",
	Schema: domain.OutputSchema{
		Fields: []domain.SchemaField{
			{Name: "brokers", Type: "string[]", Required: true, Label: "Broker addresses"},
			{Name: "topic", Type: "string", Required: true, Label: "Default topic"},
			{Name: "topic_field", Type: "string", Label: "Topic from event field (overrides default)"},
			{Name: "message_key", Type: "string", Label: "Static message key (for partition affinity)"},
			{Name: "message_key_field", Type: "string", Label: "Message key from event field (e.g., hostname, rule)"},
			{Name: "sasl", Type: "enum", Values: []string{"", "plain", "scram_sha256", "scram_sha512"}, Label: "SASL Mechanism"},
			{Name: "username", Type: "string", Label: "Username"},
			{Name: "password", Type: "string", Secret: true, Label: "Password"},
			{Name: "tls_enabled", Type: "bool", Default: false, Label: "Enable TLS"},
			{Name: "insecure_skip_verify", Type: "bool", Default: false, Label: "Skip TLS Certificate Verification"},
			{Name: "tls_ca", Type: "string", Label: "CA Certificate File"},
			{Name: "tls_cert", Type: "string", Label: "Client Certificate File"},
			{Name: "tls_key", Type: "string", Secret: true, Label: "Client Key File"},
			{Name: "compression", Type: "enum", Values: []string{"none", "gzip", "snappy", "lz4", "zstd"}, Default: "none", Label: "Compression"},
			{Name: "balancer", Type: "enum", Values: []string{"", "round_robin", "least_backup", "sticky"}, Default: "", Label: "Partition Balancer"},
			{Name: "required_acks", Type: "enum", Values: []string{"all", "one", "none"}, Default: "all", Label: "Required ACKs"},
			{Name: "client_id", Type: "string", Label: "Client ID"},
			{Name: "async", Type: "bool", Default: false, Label: "Async Produce"},
			{Name: "auto_create_topic", Type: "bool", Default: false, Label: "Allow Auto Topic Creation"},
		},
	},
}

type output struct {
	client *kgo.Client
	logger *slog.Logger
	opts   []kgo.Opt
	cfg    config
}

func createOutput(raw map[string]any, deps domain.OutputDeps) (domain.OutputDriver, error) {
	var cfg config
	if err := mapstructure.Decode(raw, &cfg); err != nil {
		return nil, fmt.Errorf("kafka config: %w", err)
	}
	if err := sdk.ValidateHosts("kafka", cfg.Brokers); err != nil {
		return nil, err
	}
	if cfg.Topic == "" {
		return nil, fmt.Errorf("kafka: topic is required")
	}

	opts, err := buildClientOpts(&cfg)
	if err != nil {
		return nil, err
	}

	return &output{
		cfg:    cfg,
		opts:   opts,
		logger: sdk.ResolveLogger(deps.Logger, "kafka"),
	}, nil
}

func (o *output) Name() string { return "kafka" }

// Init creates the Kafka client connection.
func (o *output) Init(_ context.Context) error {
	client, err := kgo.NewClient(o.opts...)
	if err != nil {
		return fmt.Errorf("kafka client: %w", err)
	}
	o.client = client
	return nil
}

// Send delivers a single event to Kafka.
func (o *output) Send(ctx context.Context, event *domain.Event) error {
	if o.client == nil {
		return fmt.Errorf("kafka: %w", domain.ErrNotReady)
	}
	record, err := o.buildRecord(event)
	if err != nil {
		return err
	}

	if o.cfg.Async {
		o.client.Produce(ctx, record, o.asyncCallback)
		return nil
	}

	return o.client.ProduceSync(ctx, record).FirstErr()
}

// SendBatch delivers multiple events to Kafka.
func (o *output) SendBatch(ctx context.Context, events []*domain.Event) error {
	if o.client == nil {
		return fmt.Errorf("kafka: %w", domain.ErrNotReady)
	}
	records := make([]*kgo.Record, 0, len(events))
	for _, event := range events {
		record, err := o.buildRecord(event)
		if err != nil {
			return err
		}
		records = append(records, record)
	}

	if o.cfg.Async {
		for _, r := range records {
			o.client.Produce(ctx, r, o.asyncCallback)
		}
		return nil
	}

	return o.client.ProduceSync(ctx, records...).FirstErr()
}

// HealthCheck tests the Kafka broker connection.
func (o *output) HealthCheck(ctx context.Context) error {
	if o.client == nil {
		return fmt.Errorf("kafka: %w", domain.ErrNotReady)
	}
	return o.client.Ping(ctx)
}

// Close shuts down the Kafka producer. franz-go flushes buffered records internally.
func (o *output) Close() error {
	if o.client != nil {
		o.client.Close()
	}
	return nil
}

// asyncCallback handles produce results for async mode.
func (o *output) asyncCallback(_ *kgo.Record, err error) {
	if err != nil {
		o.logger.Error("async produce failed", "error", err)
	}
}
