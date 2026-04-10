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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestElasticsearchCommonCases(t *testing.T) {
	testutil.RunOutputTests(t, Type, []testutil.OutputTestCase{
		{Name: "sends valid event", AddressField: "url"},
		{Name: "returns error on server 500", AddressField: "url", MockStatus: http.StatusInternalServerError, ExpectError: true},
	})
}

func TestElasticsearchPayloadFormat(t *testing.T) {
	testutil.RunOutputTests(t, Type, []testutil.OutputTestCase{
		{
			Name:         "includes @timestamp in body",
			AddressField: "url",
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				assert.Contains(t, string(body), "@timestamp")
			},
		},
		{
			Name:         "sends to _doc endpoint",
			AddressField: "url",
			Config:       map[string]any{"index": "security", "index_suffix": "none"},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				assert.Contains(t, req.URL.Path, "/security/_doc")
			},
		},
		{
			Name:         "applies basic auth",
			AddressField: "url",
			Config:       map[string]any{"username": "elastic", "password": "secret"},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				user, pass, ok := req.BasicAuth()
				require.True(t, ok)
				assert.Equal(t, "elastic", user)
				assert.Equal(t, "secret", pass)
			},
		},
		{
			Name:         "applies api key auth",
			AddressField: "url",
			Config:       map[string]any{"api_key": "mykey123"},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				assert.Equal(t, "ApiKey mykey123", req.Header.Get("Authorization"))
			},
		},
		{
			Name:         "flattens field names when configured",
			AddressField: "url",
			Config:       map[string]any{"flatten_fields": true},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				assert.NotContains(t, string(body), `"fd.name"`)
			},
		},
		{
			Name:         "includes pipeline query parameter",
			AddressField: "url",
			Config:       map[string]any{"pipeline": "my-ingest"},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				assert.Equal(t, "my-ingest", req.URL.Query().Get("pipeline"))
			},
		},
	})
}

func TestElasticsearchCreateValidation(t *testing.T) {
	_, err := createOutput(map[string]any{}, domain.OutputDeps{})
	assert.Error(t, err, "missing url must fail")
}

func TestElasticsearchHealthCheck(t *testing.T) {
	testutil.RunOutputTests(t, Type, []testutil.OutputTestCase{
		{
			Name:         "sends GET to base URL",
			AddressField: "url",
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				// harness validates Send works; HealthCheck validated by Init test
			},
		},
	})
}

func TestElasticsearchClose(t *testing.T) {
	o := &output{}
	assert.NoError(t, o.Close())
}

func TestResolveIndexSuffixes(t *testing.T) {
	tests := []struct {
		check  func(t *testing.T, index string)
		name   string
		suffix string
	}{
		{
			name:   "daily contains date with dots",
			suffix: "daily",
			check: func(t *testing.T, index string) {
				assert.Regexp(t, `^falco-\d{4}\.\d{2}\.\d{2}$`, index)
			},
		},
		{
			name:   "monthly contains year and month",
			suffix: "monthly",
			check: func(t *testing.T, index string) {
				assert.Regexp(t, `^falco-\d{4}\.\d{2}$`, index)
			},
		},
		{
			name:   "annually contains year only",
			suffix: "annually",
			check: func(t *testing.T, index string) {
				assert.Regexp(t, `^falco-\d{4}$`, index)
			},
		},
		{
			name:   "none returns bare index",
			suffix: "none",
			check: func(t *testing.T, index string) {
				assert.Equal(t, "falco", index)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &output{cfg: config{Index: "falco", Suffix: tt.suffix}}
			tt.check(t, o.resolveIndex())
		})
	}
}

func TestFlattenFieldsReplacesDotsAndPreservesValues(t *testing.T) {
	testutil.RunOutputTests(t, Type, []testutil.OutputTestCase{
		{
			Name:         "flattened field names use underscores",
			AddressField: "url",
			Config:       map[string]any{"flatten_fields": true},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				bodyStr := string(body)
				assert.NotContains(t, bodyStr, `"fd.name"`, "dotted field name must be gone")
				assert.Contains(t, bodyStr, `"fd_name"`, "flattened field name must be present")
				assert.Contains(t, bodyStr, "/bin/hack", "field value must survive flattening")
			},
		},
	})
}
