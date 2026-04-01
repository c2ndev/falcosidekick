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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestWebhookCommonCases(t *testing.T) {
	testutil.RunOutputTests(t, Type, testutil.CreateCommonTestCases())
}

func TestWebhookSpecificCases(t *testing.T) {
	testutil.RunOutputTests(t, Type, []testutil.OutputTestCase{
		{
			Name: "sends POST by default",
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				t.Helper()
				assert.Equal(t, http.MethodPost, req.Method)
				assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			},
		},
		{
			Name:   "sends PUT when configured",
			Config: map[string]any{"method": "PUT"},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				t.Helper()
				assert.Equal(t, http.MethodPut, req.Method)
			},
		},
		{
			Name: "includes custom headers",
			Config: map[string]any{
				"customheaders": map[string]string{
					"X-Custom":      "value",
					"Authorization": "Bearer token",
				},
			},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				t.Helper()
				assert.Equal(t, "value", req.Header.Get("X-Custom"))
				assert.Equal(t, "Bearer token", req.Header.Get("Authorization"))
			},
		},
		{
			Name:        "returns error on 500",
			MockStatus:  http.StatusInternalServerError,
			ExpectError: true,
		},
	})
}

func TestWebhookCreateValidation(t *testing.T) {
	t.Run("healthcheck success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		o, err := Type.New(map[string]any{"address": server.URL}, domain.OutputDeps{})
		require.NoError(t, err)
		assert.NoError(t, o.HealthCheck(context.Background()))
	})

	t.Run("healthcheck failure", func(t *testing.T) {
		o, err := Type.New(map[string]any{"address": "http://127.0.0.1:1"}, domain.OutputDeps{})
		require.NoError(t, err)
		assert.Error(t, o.HealthCheck(context.Background()))
	})

	t.Run("send to unreachable host", func(t *testing.T) {
		o, err := Type.New(map[string]any{"address": "http://127.0.0.1:1"}, domain.OutputDeps{})
		require.NoError(t, err)
		assert.Error(t, o.Send(context.Background(), testutil.CreateValidEvent()))
	})

	t.Run("init and close", func(t *testing.T) {
		o, err := Type.New(map[string]any{"address": "http://example.com"}, domain.OutputDeps{})
		require.NoError(t, err)
		assert.NoError(t, o.Init(context.Background()))
		assert.NoError(t, o.Close())
	})

	tests := []struct {
		cfg     map[string]any
		name    string
		wantErr bool
	}{
		{
			name:    "missing address",
			cfg:     map[string]any{},
			wantErr: true,
		},
		{
			name: "valid minimal config",
			cfg:  map[string]any{"address": "http://example.com"},
		},
		{
			name: "method defaults to POST",
			cfg:  map[string]any{"address": "http://example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o, err := Type.New(tt.cfg, domain.OutputDeps{})
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "webhook", o.Name())
		})
	}
}
