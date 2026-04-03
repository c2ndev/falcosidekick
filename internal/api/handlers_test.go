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
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

var (
	enricherConfig = pipeline.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	}
	outputWorkerConfig = pipeline.OutputWorkerConfig{
		QueueSize: 100,
		Workers:   1,
		Retry: pipeline.RetryConfig{
			MaxAttempts: 1,
		},
	}
)

type testOutput struct {
	sendFunc func(ctx context.Context, event *domain.Event) error
	name     string
}

func (m *testOutput) Name() string                        { return m.name }
func (m *testOutput) Init(_ context.Context) error        { return nil }
func (m *testOutput) HealthCheck(_ context.Context) error { return nil }
func (m *testOutput) Close() error                        { return nil }
func (m *testOutput) Send(ctx context.Context, event *domain.Event) error {
	if m.sendFunc != nil {
		return m.sendFunc(ctx, event)
	}
	return nil
}

func buildTestServer(t *testing.T, outputs []domain.Output) *Server {
	t.Helper()
	enricher, _ := pipeline.NewEnricher(enricherConfig)
	priorities := make(map[string]domain.Priority)
	for _, o := range outputs {
		priorities[o.Name()] = domain.PriorityDebug
	}
	router := pipeline.NewRouter(priorities)
	dispatcher := pipeline.NewDispatcher(outputs, pipeline.OutputWorkerConfig{
		QueueSize: 100,
		Workers:   1,
		Retry:     pipeline.RetryConfig{MaxAttempts: 1},
	}, nil)

	p, err := pipeline.NewPipeline(
		enricher,
		nil,
		router,
		dispatcher,
		nil,
	)
	if err != nil {
		t.Fatalf("build pipeline: %v", err)
	}

	ctx := context.Background()
	p.Start(ctx)

	srv, err := NewServer(ServerConfig{
		Pipeline: p,
	})
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	return srv
}

func createValidEventJSON() []byte {
	event := domain.Event{
		Time:         time.Now().UTC(),
		OutputFields: map[string]interface{}{"proc.name": "bash"},
		Tags:         []string{"test"},
		Rule:         "Test rule",
		Output:       "test output",
		Source:       "syscall",
		Hostname:     "node-1",
		Priority:     domain.PriorityWarning,
	}
	data, _ := event.MarshalJSON()
	return data
}

func TestHandlePostEventValid(t *testing.T) {
	var received atomic.Int64
	srv := buildTestServer(t, []domain.Output{
		&testOutput{name: "test", sendFunc: func(_ context.Context, _ *domain.Event) error {
			received.Add(1)
			return nil
		}},
	})

	ctx := context.Background()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewReader(createValidEventJSON()))
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

	ctx := context.Background()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewReader([]byte(`{invalid`)))
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

	event := map[string]interface{}{
		"time":   time.Now().UTC(),
		"source": "syscall",
	}
	data, _ := json.Marshal(event)

	ctx := context.Background()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewReader(data))
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

	ctx := context.Background()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/healthz", http.NoBody)

	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), `"status":"ok"`)
}

func TestServerDefaults(t *testing.T) {
	enricher, err := pipeline.NewEnricher(enricherConfig)
	require.NoError(t, err)
	p, err := pipeline.NewPipeline(
		enricher,
		nil,
		pipeline.NewRouter(nil),
		pipeline.NewDispatcher(nil, outputWorkerConfig, nil),
		nil,
	)
	require.NoError(t, err)

	srv, err := NewServer(ServerConfig{Pipeline: p})
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0:2801", srv.address)
}

func TestNewServerRejectsNilPipeline(t *testing.T) {
	_, err := NewServer(ServerConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pipeline is required")
}
