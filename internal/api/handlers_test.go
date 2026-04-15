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

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/metrics"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

var defaultTestOutputConfig = output.RuntimeConfig{
	QueueSize: 100,
	Workers:   1,
	Retry: &output.RetryConfig{
		MaxAttempts:     1,
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     100 * time.Millisecond,
		Multiplier:      2.0,
	},
	CircuitBreaker: &output.CircuitBreakerConfig{
		FailureThreshold: 5,
		SuccessThreshold: 2,
		ResetTimeout:     30 * time.Second,
	},
}

func buildTestServer(t *testing.T, outputs []*pipeline.Output) *Server {
	t.Helper()
	enricher, _ := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	dispatcher := pipeline.NewDispatcher(outputs)

	p, err := pipeline.NewPipeline(enricher, dispatcher, nil)
	if err != nil {
		t.Fatalf("build pipeline: %v", err)
	}

	p.Start()

	srv, err := NewServer(&ServerConfig{Pipeline: p})
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	return srv
}

func createValidEventJSON() []byte {
	evt := event.Event{
		Time:         time.Now().UTC(),
		OutputFields: map[string]interface{}{"proc.name": "bash"},
		Tags:         []string{"test"},
		Rule:         "Test rule",
		Output:       "test output",
		Source:       "syscall",
		Hostname:     "node-1",
		Priority:     event.PriorityWarning,
	}
	data, _ := evt.MarshalJSON()
	return data
}

func TestHandlePostEventValid(t *testing.T) {
	var received atomic.Int64
	cfg := defaultTestOutputConfig
	cfg.MinPriority = event.PriorityDebug
	out := pipeline.NewOutput(&testutil.MockDriver{DriverName: "test", SendFunc: func(_ context.Context, _ *event.Event) error {
		received.Add(1)
		return nil
	}}, &cfg, nil)

	srv := buildTestServer(t, []*pipeline.Output{out})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(createValidEventJSON()))
	req.Header.Set("Content-Type", "application/json")

	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int64(1), received.Load())
}

func TestHandlePostEventInvalidJSON(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader([]byte(`{invalid`)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 400, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "error")
}

func TestHandlePostEventMissingRule(t *testing.T) {
	srv := buildTestServer(t, nil)

	evt := map[string]interface{}{
		"time":   time.Now().UTC(),
		"source": "syscall",
	}
	data, _ := json.Marshal(evt)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")

	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 400, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "rule is required")
}

func TestHandleGetHealthz(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", http.NoBody)

	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), `"status":"ok"`)
}

func TestHandleGetVersion(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/version", http.NoBody)

	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "version")
}

func TestServerDefaults(t *testing.T) {
	enricher, err := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	require.NoError(t, err)
	p, err := pipeline.NewPipeline(enricher, pipeline.NewDispatcher(nil), nil)
	require.NoError(t, err)

	srv, err := NewServer(&ServerConfig{Pipeline: p})
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0:2801", srv.address)
}

func TestNewServerRejectsNilPipeline(t *testing.T) {
	_, err := NewServer(&ServerConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pipeline is required")
}

func buildTestServerWithDB(t *testing.T, db core.Database) *Server {
	t.Helper()
	enricher, _ := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	dispatcher := pipeline.NewDispatcher(nil)
	p, err := pipeline.NewPipeline(enricher, dispatcher, nil)
	require.NoError(t, err)
	p.Start()

	srv, err := NewServer(&ServerConfig{Pipeline: p, Database: db})
	require.NoError(t, err)
	return srv
}

func TestHandleGetConfigProvisioned(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.Provision(t.Context(), &core.ProvisionRequest{
		Config:  &core.Config{ListenPort: 2801, LogLevel: core.LogLevelInfo},
		Outputs: map[string]map[string]any{},
	}))

	srv := buildTestServerWithDB(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/config", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "listen_port")
}

func TestHandleGetConfigEmpty(t *testing.T) {
	db := database.NewMemory()
	srv := buildTestServerWithDB(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/config", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
}

func TestHandleGetConfigNoDatabase(t *testing.T) {
	srv := buildTestServerWithDB(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/config", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 503, resp.StatusCode)
}

func TestHandleGetOutputsProvisioned(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.Provision(t.Context(), &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"slack":  {"webhookurl": "https://test"},
			"memory": {"capacity": 5000},
		},
	}))

	srv := buildTestServerWithDB(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/outputs", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "slack")
	assert.Contains(t, string(body), "memory")
}

func TestHandleGetOutputsEmpty(t *testing.T) {
	db := database.NewMemory()
	srv := buildTestServerWithDB(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/outputs", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
}

func TestHandleGetOutputsNoDatabase(t *testing.T) {
	srv := buildTestServerWithDB(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/outputs", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 503, resp.StatusCode)
}

func TestStartAndShutdown(t *testing.T) {
	srv := buildTestServer(t, nil)

	started := make(chan struct{})
	go func() {
		close(started)
		_ = srv.Start()
	}()
	<-started

	time.Sleep(50 * time.Millisecond)
	require.NoError(t, srv.Shutdown())
}

func TestHandlePostEventWithMetrics(t *testing.T) {
	collector := metrics.NewCollector()
	enricher, _ := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	dispatcher := pipeline.NewDispatcher(nil)
	p, err := pipeline.NewPipeline(enricher, dispatcher, collector)
	require.NoError(t, err)
	p.Start()

	srv, err := NewServer(&ServerConfig{Pipeline: p, Metrics: collector})
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(createValidEventJSON()))
	req.Header.Set("Content-Type", "application/json")

	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
}

func TestNewServerWithMetricsRegistry(t *testing.T) {
	enricher, _ := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	p, err := pipeline.NewPipeline(enricher, pipeline.NewDispatcher(nil), nil)
	require.NoError(t, err)

	reg := prometheus.NewRegistry()
	srv, err := NewServer(&ServerConfig{Pipeline: p, Registry: reg})
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
}

type errorDB struct{ core.Database }

func (e *errorDB) GetConfig(_ context.Context) (*core.ConfigEntry, error) {
	return nil, errors.New("db failure")
}

func (e *errorDB) GetOutputConfigs(_ context.Context) (map[string]core.OutputConfigEntry, error) {
	return nil, errors.New("db failure")
}

func (e *errorDB) Close() error { return nil }

func TestHandleGetConfigDBError(t *testing.T) {
	srv := buildTestServerWithDB(t, &errorDB{})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/config", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 500, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "db failure")
}

func TestHandleGetOutputsDBError(t *testing.T) {
	srv := buildTestServerWithDB(t, &errorDB{})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/outputs", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 500, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "db failure")
}
