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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

func TestKafkaCreateValidation(t *testing.T) {
	tests := []struct {
		config map[string]any
		name   string
	}{
		{config: map[string]any{"topic": "test"}, name: "missing brokers"},
		{config: map[string]any{"brokers": []string{"http://localhost:9092"}}, name: "missing topic"},
		{config: map[string]any{}, name: "both missing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := createOutput(tt.config, domain.OutputDeps{})
			assert.Error(t, err)
		})
	}
}

func TestKafkaCreateSuccess(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers": []string{"http://localhost:9092"},
		"topic":   "falco-events",
	}, domain.OutputDeps{})
	require.NoError(t, err)
	assert.Equal(t, "kafka", driver.Name())
}

func TestKafkaImplementsBatchSender(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers": []string{"http://localhost:9092"},
		"topic":   "falco-events",
	}, domain.OutputDeps{})
	require.NoError(t, err)

	_, ok := driver.(domain.BatchSender)
	assert.True(t, ok, "kafka must implement BatchSender")
}

func TestResolveACKs(t *testing.T) {
	tests := []struct {
		input string
		want  kgo.Acks
	}{
		{"all", kgo.AllISRAcks()},
		{"one", kgo.LeaderAck()},
		{"none", kgo.NoAck()},
		{"", kgo.AllISRAcks()},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := resolveACKs(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveSASL(t *testing.T) {
	tests := []struct {
		name    string
		sasl    string
		wantNil bool
		wantErr bool
	}{
		{"empty returns nil", "", true, false},
		{"none returns nil", "none", true, false},
		{"plain returns opt", "plain", false, false},
		{"scram_sha256 returns opt", "scram_sha256", false, false},
		{"scram_sha512 returns opt", "scram_sha512", false, false},
		{"unknown returns error", "kerberos", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config{SASL: tt.sasl, Username: "user", Password: "pass"}
			opt, err := resolveSASL(cfg)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, opt)
			} else {
				assert.NotNil(t, opt)
			}
		})
	}
}

func TestResolveCompression(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"gzip", "gzip"},
		{"snappy", "snappy"},
		{"lz4", "lz4"},
		{"zstd", "zstd"},
		{"none explicit", "none"},
		{"empty defaults to none", ""},
		{"uppercase normalizes", "GZIP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := resolveCompression(tt.input)
			assert.Len(t, opts, 1, "must return exactly one option")
		})
	}
}

func TestResolveBalancer(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{"round_robin", "round_robin", 1},
		{"least_backup", "least_backup", 1},
		{"sticky", "sticky", 1},
		{"empty returns nil", "", 0},
		{"unknown returns nil", "random", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := resolveBalancer(tt.input)
			assert.Len(t, opts, tt.wantLen)
		})
	}
}

func TestCreateOutputAsync(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers": []string{"http://localhost:9092"},
		"topic":   "events",
		"async":   true,
	}, domain.OutputDeps{})
	require.NoError(t, err)

	o, ok := driver.(*output)
	require.True(t, ok)
	assert.True(t, o.cfg.Async)
}

func TestCreateOutputTopicCreation(t *testing.T) {
	tests := []struct {
		name          string
		topicCreation bool
	}{
		{"enabled", true},
		{"disabled", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver, err := createOutput(map[string]any{
				"brokers":           []string{"http://localhost:9092"},
				"topic":             "events",
				"auto_create_topic": tt.topicCreation,
			}, domain.OutputDeps{})
			require.NoError(t, err)
			assert.Equal(t, "kafka", driver.Name())
		})
	}
}

func TestCreateOutputClientID(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers":   []string{"http://localhost:9092"},
		"topic":     "events",
		"client_id": "my-producer",
	}, domain.OutputDeps{})
	require.NoError(t, err)
	assert.NotNil(t, driver)
}

func TestCreateOutputTLS(t *testing.T) {
	tests := []struct {
		config map[string]any
		name   string
	}{
		{
			name: "tls with default insecure_skip_verify",
			config: map[string]any{
				"brokers":     []string{"http://localhost:9092"},
				"topic":       "events",
				"tls_enabled": true,
			},
		},
		{
			name: "tls with insecure_skip_verify false",
			config: map[string]any{
				"brokers":              []string{"http://localhost:9092"},
				"topic":                "events",
				"tls_enabled":          true,
				"insecure_skip_verify": false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver, err := createOutput(tt.config, domain.OutputDeps{})
			require.NoError(t, err)
			assert.NotNil(t, driver)
		})
	}
}

func TestCreateOutputSASLVariants(t *testing.T) {
	tests := []struct {
		name string
		sasl string
	}{
		{"plain", "plain"},
		{"scram256", "scram_sha256"},
		{"scram512", "scram_sha512"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver, err := createOutput(map[string]any{
				"brokers":  []string{"http://localhost:9092"},
				"topic":    "events",
				"sasl":     tt.sasl,
				"username": "user",
				"password": "pass",
			}, domain.OutputDeps{})
			require.NoError(t, err)
			assert.NotNil(t, driver)
		})
	}
}

func TestCreateOutputSASLInvalid(t *testing.T) {
	_, err := createOutput(map[string]any{
		"brokers": []string{"http://localhost:9092"},
		"topic":   "events",
		"sasl":    "kerberos",
	}, domain.OutputDeps{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported SASL")
}

func TestCreateOutputAllOptions(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers":           []string{"http://broker1:9092", "http://broker2:9092"},
		"topic":             "falco",
		"sasl":              "plain",
		"username":          "u",
		"password":          "p",
		"tls_enabled":       true,
		"client_id":         "cid",
		"compression":       "zstd",
		"balancer":          "round_robin",
		"required_acks":     "one",
		"async":             true,
		"auto_create_topic": true,
	}, domain.OutputDeps{})
	require.NoError(t, err)

	o, ok := driver.(*output)
	require.True(t, ok)
	assert.Equal(t, "falco", o.cfg.Topic)
	assert.True(t, o.cfg.Async)
}

func TestCloseNilClient(t *testing.T) {
	o := &output{cfg: config{Topic: "test"}}
	err := o.Close()
	assert.NoError(t, err)
}

func TestCreateOutputMultiBroker(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers": []string{"http://b1:9092", "http://b2:9092", "http://b3:9092"},
		"topic":   "t",
	}, domain.OutputDeps{})
	require.NoError(t, err)
	assert.Equal(t, "kafka", driver.Name())
}

func TestInitCreateClient(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers": []string{"http://localhost:19092"},
		"topic":   "events",
	}, domain.OutputDeps{})
	require.NoError(t, err)

	o, ok := driver.(*output)
	require.True(t, ok)
	assert.Nil(t, o.client, "client must be nil before Init")

	err = o.Init(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, o.client, "client must be set after Init")
	_ = o.Close()
}

func TestCloseWithClient(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers": []string{"http://localhost:19092"},
		"topic":   "events",
	}, domain.OutputDeps{})
	require.NoError(t, err)

	o := driver.(*output)
	require.NoError(t, o.Init(context.Background()))
	assert.NotNil(t, o.client)

	err = o.Close()
	assert.NoError(t, err)
}

func TestSendSyncWithClient(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers": []string{"http://localhost:19092"},
		"topic":   "events",
	}, domain.OutputDeps{})
	require.NoError(t, err)

	o := driver.(*output)
	require.NoError(t, o.Init(context.Background()))
	defer func() { _ = o.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = o.Send(ctx, &domain.Event{
		Rule:         "test",
		Priority:     domain.PriorityWarning,
		Time:         time.Now(),
		Source:       "syscall",
		OutputFields: map[string]interface{}{"a": "b"},
	})
	// error expected - no broker, but we exercise the sync produce path
	assert.Error(t, err)
}

func TestSendAsyncWithClient(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers": []string{"http://localhost:19092"},
		"topic":   "events",
		"async":   true,
	}, domain.OutputDeps{})
	require.NoError(t, err)

	o := driver.(*output)
	require.NoError(t, o.Init(context.Background()))
	defer func() { _ = o.Close() }()

	err = o.Send(context.Background(), &domain.Event{
		Rule:         "test",
		Priority:     domain.PriorityWarning,
		Time:         time.Now(),
		Source:       "syscall",
		OutputFields: map[string]interface{}{"a": "b"},
	})
	// async produce returns nil immediately
	assert.NoError(t, err)
}

func TestSendBatchSyncWithClient(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers": []string{"http://localhost:19092"},
		"topic":   "events",
	}, domain.OutputDeps{})
	require.NoError(t, err)

	o := driver.(*output)
	require.NoError(t, o.Init(context.Background()))
	defer func() { _ = o.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	events := []*domain.Event{
		{Rule: "r1", Priority: domain.PriorityWarning, Time: time.Now(), Source: "syscall", OutputFields: map[string]interface{}{"a": "b"}},
		{Rule: "r2", Priority: domain.PriorityError, Time: time.Now(), Source: "syscall", OutputFields: map[string]interface{}{"c": "d"}},
	}
	err = o.SendBatch(ctx, events)
	// error expected - no broker
	assert.Error(t, err)
}

func TestSendBatchAsyncWithClient(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers": []string{"http://localhost:19092"},
		"topic":   "events",
		"async":   true,
	}, domain.OutputDeps{})
	require.NoError(t, err)

	o := driver.(*output)
	require.NoError(t, o.Init(context.Background()))
	defer func() { _ = o.Close() }()

	events := []*domain.Event{
		{Rule: "r1", Priority: domain.PriorityWarning, Time: time.Now(), Source: "syscall", OutputFields: map[string]interface{}{"a": "b"}},
	}
	err = o.SendBatch(context.Background(), events)
	assert.NoError(t, err)
}

func TestHealthCheckWithClient(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"brokers": []string{"http://localhost:19092"},
		"topic":   "events",
	}, domain.OutputDeps{})
	require.NoError(t, err)

	o := driver.(*output)
	require.NoError(t, o.Init(context.Background()))
	defer func() { _ = o.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = o.HealthCheck(ctx)
	// error expected - no broker, but exercises the ping path
	assert.Error(t, err)
}
