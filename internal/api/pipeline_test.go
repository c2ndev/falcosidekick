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
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

type layoutErrorDB struct{ core.Database }

func (l *layoutErrorDB) GetOutputConfigs(_ context.Context) (map[string]core.OutputConfigEntry, error) {
	return map[string]core.OutputConfigEntry{}, nil
}

func (l *layoutErrorDB) GetPipelineLayout(_ context.Context) (*core.PipelineLayout, error) {
	return nil, errors.New("layout failed")
}

func (l *layoutErrorDB) Close() error { return nil }

// --- /api/v1/pipeline/status ---

func TestHandlePipelineStatus_NoOutputs(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/status", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), `"outputs":[]`, "empty status must serialize as empty slice, not null")
}

func TestHandlePipelineStatus_WithOutputs(t *testing.T) {
	out1 := pipeline.NewOutput(&testutil.MockDriver{DriverName: "slack"}, &defaultTestOutputConfig, nil)
	out2 := pipeline.NewOutput(&testutil.MockDriver{DriverName: "elasticsearch"}, &defaultTestOutputConfig, nil)
	srv := buildTestServer(t, []*pipeline.Output{out1, out2})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/status", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	var got struct {
		Outputs []pipeline.OutputStatus `json:"outputs"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Len(t, got.Outputs, 2)

	names := []string{got.Outputs[0].Name, got.Outputs[1].Name}
	assert.ElementsMatch(t, []string{"slack", "elasticsearch"}, names)
}

// --- /api/v1/pipeline/status/:name ---

func TestHandlePipelineStatusByName_Hit(t *testing.T) {
	out := pipeline.NewOutput(&testutil.MockDriver{DriverName: "slack"}, &defaultTestOutputConfig, nil)
	srv := buildTestServer(t, []*pipeline.Output{out})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/status/slack", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	var got pipeline.OutputStatus
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "slack", got.Name)
}

func TestHandlePipelineStatusByName_Miss(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/status/missing", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 404, resp.StatusCode)
}

// --- /api/v1/pipeline/outputs ---

func TestHandlePipelineOutputs_Masked(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.Provision(t.Context(), &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"elasticsearch": {"url": "https://es:9200", "password": "hunter2"},
			"slack":         {"url": "https://hooks.slack.com/x", "channel": "#c"},
		},
	}))
	cat, err := catalog.New([]output.Type{
		{
			Name: "elasticsearch",
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return &testutil.MockDriver{DriverName: "elasticsearch"}, nil
			},
			Schema: output.Schema{Fields: []output.SchemaField{
				{Name: "url", Type: "string"},
				{Name: "password", Type: "string", Secret: true},
			}},
		},
		{
			Name: "slack",
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return &testutil.MockDriver{DriverName: "slack"}, nil
			},
			Schema: output.Schema{Fields: []output.SchemaField{
				{Name: "url", Type: "string"},
				{Name: "channel", Type: "string"},
			}},
		},
	})
	require.NoError(t, err)

	srv := buildTestServerWithDBAndCatalog(t, db, cat)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)

	var got map[string]core.OutputConfigEntry
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))

	assert.Equal(t, SecretMask, got["elasticsearch"].Config["password"], "secret field must be masked")
	assert.Equal(t, "https://es:9200", got["elasticsearch"].Config["url"])
	assert.Equal(t, "https://hooks.slack.com/x", got["slack"].Config["url"])
}

func TestHandlePipelineOutputs_NoDatabase(t *testing.T) {
	srv := buildTestServerWithDB(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 503, resp.StatusCode)
}

func TestHandlePipelineOutputs_DBError(t *testing.T) {
	srv := buildTestServerWithDB(t, &errorDB{})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "db failure")
}

// --- /api/v1/pipeline/outputs/:name ---

func TestHandlePipelineOutputByName_Hit(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.Provision(t.Context(), &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"elasticsearch": {"url": "https://es:9200", "password": "hunter2"},
		},
	}))
	cat, err := catalog.New([]output.Type{{
		Name: "elasticsearch",
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: "elasticsearch"}, nil
		},
		Schema: output.Schema{Fields: []output.SchemaField{
			{Name: "url", Type: "string"},
			{Name: "password", Type: "string", Secret: true},
		}},
	}})
	require.NoError(t, err)

	srv := buildTestServerWithDBAndCatalog(t, db, cat)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/elasticsearch", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	var got core.OutputConfigEntry
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "elasticsearch", got.Name)
	assert.Equal(t, SecretMask, got.Config["password"])
	assert.Equal(t, "https://es:9200", got.Config["url"])
}

func TestHandlePipelineOutputByName_Miss(t *testing.T) {
	db := database.NewMemory()
	srv := buildTestServerWithDB(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/absent", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 404, resp.StatusCode)
}

func TestHandlePipelineOutputByName_NoDatabase(t *testing.T) {
	srv := buildTestServerWithDB(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/foo", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 503, resp.StatusCode)
}

func TestHandlePipelineOutputByName_BackendFailureReturns500(t *testing.T) {
	srv := buildTestServerWithDB(t, &errorDB{})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/foo", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode, "backend read failure must surface as 500, not 404")
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "db failure")
}

// --- /api/v1/pipeline/outputs/types ---

func TestHandlePipelineOutputTypes(t *testing.T) {
	cat, err := catalog.New([]output.Type{
		{
			Name:     "slack",
			Category: "chat",
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return &testutil.MockDriver{DriverName: "slack"}, nil
			},
			Schema: output.Schema{Fields: []output.SchemaField{
				{Name: "webhook_url", Type: "string", Secret: true},
				{Name: "channel", Type: "string"},
			}},
		},
		{
			Name:     "webhook",
			Category: "webhook",
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return &testutil.MockDriver{DriverName: "webhook"}, nil
			},
			Schema: output.Schema{Fields: []output.SchemaField{
				{Name: "address", Type: "string", Required: true},
			}},
		},
	})
	require.NoError(t, err)

	srv := buildTestServerWithDBAndCatalog(t, database.NewMemory(), cat)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/types", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	var got struct {
		Types []output.Type `json:"types"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Len(t, got.Types, 2)

	names := []string{got.Types[0].Name, got.Types[1].Name}
	assert.ElementsMatch(t, []string{"slack", "webhook"}, names)
}

// --- /api/v1/pipeline/outputs/types/:name ---

func TestHandlePipelineOutputTypeByName_Hit(t *testing.T) {
	cat, err := catalog.New([]output.Type{{
		Name:     "slack",
		Category: "chat",
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: "slack"}, nil
		},
		Schema: output.Schema{Fields: []output.SchemaField{{Name: "webhook_url", Type: "string", Secret: true}}},
	}})
	require.NoError(t, err)

	srv := buildTestServerWithDBAndCatalog(t, database.NewMemory(), cat)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/types/slack", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	var got output.Type
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "slack", got.Name)
	assert.Equal(t, "chat", got.Category)
	require.Len(t, got.Schema.Fields, 1)
	assert.True(t, got.Schema.Fields[0].Secret)
}

func TestHandlePipelineOutputTypeByName_Miss(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/types/absent", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 404, resp.StatusCode)
}

// --- Route ordering: types vs :name ---

func TestHandlePipelineOutputsRouteOrdering_TypesWinsOverName(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/types", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode, "/api/v1/pipeline/outputs/types must resolve to the catalog handler, not the :name handler")

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), `"types"`)
}

// --- /api/v1/pipeline/layout ---

func TestHandlePipelineLayout_NoLayout(t *testing.T) {
	db := database.NewMemory()
	srv := buildTestServerWithDB(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/layout", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "{}", string(body))
}

func TestHandlePipelineLayout_Stored(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.SavePipelineLayout(t.Context(), &core.PipelineLayout{
		Nodes: []core.LayoutNode{{ID: "sidekick", X: 10, Y: 20}},
	}))
	srv := buildTestServerWithDB(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/layout", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	var got core.PipelineLayout
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Len(t, got.Nodes, 1)
	assert.Equal(t, "sidekick", got.Nodes[0].ID)
}

func TestHandlePipelineLayout_NoDatabase(t *testing.T) {
	srv := buildTestServerWithDB(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/layout", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 503, resp.StatusCode)
}

// --- /api/v1/pipeline (composite) ---

func TestHandlePipelineComposite(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.Provision(t.Context(), &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"slack": {"url": "https://hooks.slack.com/x"},
		},
	}))
	require.NoError(t, db.SavePipelineLayout(t.Context(), &core.PipelineLayout{
		Nodes: []core.LayoutNode{{ID: "slack", X: 1, Y: 2}},
	}))

	cat, err := catalog.New([]output.Type{{
		Name: "slack",
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: "slack"}, nil
		},
		Schema: output.Schema{Fields: []output.SchemaField{
			{Name: "url", Type: "string"},
		}},
	}})
	require.NoError(t, err)

	// Build a pipeline with one live output so status is non-empty.
	out := pipeline.NewOutput(&testutil.MockDriver{DriverName: "slack"}, &defaultTestOutputConfig, nil)
	enricher, _ := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	dispatcher := pipeline.NewDispatcher([]*pipeline.Output{out})
	p, err := pipeline.NewPipeline(enricher, dispatcher, nil)
	require.NoError(t, err)
	p.Start(context.Background(), func() {})

	srv, err := NewServer(&ServerConfig{
		Pipeline: p, Database: db, Catalog: cat,
	})
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)

	var got struct {
		Outputs map[string]core.OutputConfigEntry `json:"outputs"`
		Layout  *core.PipelineLayout              `json:"layout"`
		Status  []pipeline.OutputStatus           `json:"status"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))

	require.Contains(t, got.Outputs, "slack")
	assert.Equal(t, "https://hooks.slack.com/x", got.Outputs["slack"].Config["url"])

	require.Len(t, got.Status, 1)
	assert.Equal(t, "slack", got.Status[0].Name)

	require.NotNil(t, got.Layout)
	require.Len(t, got.Layout.Nodes, 1)
	assert.Equal(t, "slack", got.Layout.Nodes[0].ID)
}

func TestHandlePipelineComposite_NoDatabase(t *testing.T) {
	srv := buildTestServerWithDB(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 503, resp.StatusCode)
}

func TestHandlePipelineComposite_LayoutError(t *testing.T) {
	srv := buildTestServerWithDB(t, &layoutErrorDB{})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "layout failed")
}

// --- /api/v1/config with secret masking ---

func TestHandleGetConfig_MaskingHelperWired(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.Provision(t.Context(), &core.ProvisionRequest{
		Config: &core.Config{ListenAddress: "0.0.0.0", ListenPort: 2801, LogLevel: core.LogLevelInfo, LogFormat: core.LogFormatText},
	}))
	srv := buildTestServerWithDB(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/config", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)

	var got core.ConfigEntry
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.NotNil(t, got.Config)
	assert.Equal(t, "0.0.0.0", got.Config.ListenAddress)
	assert.Equal(t, 2801, got.Config.ListenPort)
}

// --- Guard: event struct import is used ---

var _ = event.Event{}
