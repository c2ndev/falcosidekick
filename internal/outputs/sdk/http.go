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
	"crypto/tls"
	"net/http"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

const (
	defaultTimeout         = 10 * time.Second
	defaultTLSMinVersion   = tls.VersionTLS12
	defaultMaxIdleConns    = 10
	defaultIdleConnTimeout = 30 * time.Second
)

// HTTPConfig holds shared HTTP client and auth settings for outputs.
// Outputs embed this struct to get TLS, headers, and authentication for free.
type HTTPConfig struct {
	Headers            map[string]string `mapstructure:"headers"`
	Username           string            `mapstructure:"username"`
	Password           string            `mapstructure:"password"`
	BearerToken        string            `mapstructure:"bearer_token"`
	InsecureSkipVerify bool              `mapstructure:"insecure_skip_verify"`
}

// HTTPConfigSchemaFields returns schema fields common to all HTTP outputs.
// Outputs append their specific fields to this base.
func HTTPConfigSchemaFields() []domain.SchemaField {
	return []domain.SchemaField{
		{Name: "username", Type: "string", Label: "Username (Basic Auth)"},
		{Name: "password", Type: "string", Secret: true, Label: "Password (Basic Auth)"},
		{Name: "bearer_token", Type: "string", Secret: true, Label: "Bearer Token"},
		{Name: "headers", Type: "map", Label: "Custom HTTP Headers"},
		{Name: "insecure_skip_verify", Type: "bool", Default: false, Label: "Skip TLS Certificate Verification"},
	}
}

// BuildHTTPClient creates an HTTP client from shared config.
func BuildHTTPClient(cfg *HTTPConfig) *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // user-configurable TLS verification
				MinVersion:         defaultTLSMinVersion,
			},
			MaxIdleConns:    defaultMaxIdleConns,
			IdleConnTimeout: defaultIdleConnTimeout,
		},
	}
}

// ApplyHeaders sets custom headers on an HTTP request.
func ApplyHeaders(req *http.Request, headers map[string]string) {
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}
