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

package sdk

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildHTTPClientDefault(t *testing.T) {
	cfg := &HTTPConfig{}
	client := BuildHTTPClient(cfg)

	require.NotNil(t, client)
	assert.Equal(t, defaultTimeout, client.Timeout)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestBuildHTTPClientInsecure(t *testing.T) {
	cfg := &HTTPConfig{InsecureSkipVerify: true}
	client := BuildHTTPClient(cfg)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestBuildHTTPClientTLSVersion(t *testing.T) {
	cfg := &HTTPConfig{}
	client := BuildHTTPClient(cfg)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
}

func TestApplyHeaders(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", http.NoBody)
	require.NoError(t, err)

	ApplyHeaders(req, map[string]string{
		"X-Custom": "value",
		"X-Other":  "other",
	})

	assert.Equal(t, "value", req.Header.Get("X-Custom"))
	assert.Equal(t, "other", req.Header.Get("X-Other"))
}

func TestApplyHeadersNilMap(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", http.NoBody)
	require.NoError(t, err)

	ApplyHeaders(req, nil)
	assert.Empty(t, req.Header.Get("X-Custom"))
}

func TestHTTPConfigSchemaFields(t *testing.T) {
	fields := HTTPConfigSchemaFields()

	require.NotEmpty(t, fields, "schema fields must not be empty")

	names := make(map[string]bool, len(fields))
	for _, f := range fields {
		names[f.Name] = true
	}

	assert.True(t, names["username"], "must include username field")
	assert.True(t, names["password"], "must include password field")
	assert.True(t, names["bearer_token"], "must include bearer_token field")
	assert.True(t, names["headers"], "must include headers field")
	assert.True(t, names["insecure_skip_verify"], "must include insecure_skip_verify field")

	for _, f := range fields {
		if f.Name == "password" || f.Name == "bearer_token" {
			assert.True(t, f.Secret, "%s must be marked as secret", f.Name)
		}
	}
}
