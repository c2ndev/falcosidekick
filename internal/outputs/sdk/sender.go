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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	userAgent = "falcosidekick/v3"
	// maxErrorBodyBytes caps how much of an error response body we read.
	// Prevents memory issues if a server returns a huge HTML error page.
	maxErrorBodyBytes = 4096
)

// Sender handles HTTP request execution and response checking for output drivers.
type Sender struct {
	client    *http.Client
	headers   map[string]string
	basicUser string
	basicPass string
	name      string
}

// NewSender creates a Sender with a pre-configured HTTP client.
// Auth from HTTPConfig (basic auth, bearer token) is auto-configured.
func NewSender(name string, cfg *HTTPConfig) *Sender {
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = v
	}

	s := &Sender{
		name:    name,
		client:  BuildHTTPClient(cfg),
		headers: headers,
	}

	if cfg.Username != "" {
		s.basicUser = cfg.Username
		s.basicPass = cfg.Password
	}
	if cfg.BearerToken != "" {
		s.headers["Authorization"] = "Bearer " + cfg.BearerToken
	}

	return s
}

// SetBasicAuth configures basic authentication for all requests.
func (s *Sender) SetBasicAuth(user, pass string) {
	s.basicUser = user
	s.basicPass = pass
}

// SetHeader adds a persistent header applied to every request.
func (s *Sender) SetHeader(key, value string) {
	s.headers[key] = value
}

// SendJSON marshals payload as JSON and sends with the given HTTP method.
func (s *Sender) SendJSON(ctx context.Context, method, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("%s marshal: %w", s.name, err)
	}
	return s.SendRaw(ctx, method, url, body, "application/json")
}

// SendGzipJSON marshals payload as JSON, gzip-compresses it, and sends with Content-Encoding: gzip.
func (s *Sender) SendGzipJSON(ctx context.Context, method, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("%s marshal: %w", s.name, err)
	}
	return s.SendGzipRaw(ctx, method, url, body, "application/json")
}

// SendRaw sends pre-built bytes with the given content type and HTTP method.
func (s *Sender) SendRaw(ctx context.Context, method, url string, body []byte, contentType string) error {
	req, err := s.buildRequest(ctx, method, url, body, contentType)
	if err != nil {
		return err
	}
	return s.Do(ctx, req)
}

// SendGzipRaw gzip-compresses raw bytes and sends with Content-Encoding: gzip.
func (s *Sender) SendGzipRaw(ctx context.Context, method, url string, body []byte, contentType string) error {
	compressed, err := gzipCompress(body)
	if err != nil {
		return fmt.Errorf("%s gzip: %w", s.name, err)
	}
	req, err := s.buildRequest(ctx, method, url, compressed, contentType)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Encoding", "gzip")
	return s.Do(ctx, req)
}

// SendJSONCheckBody marshals, sends, and validates the response body.
// For APIs that return HTTP 200 with error text (Slack, Teams, Discord).
func (s *Sender) SendJSONCheckBody(ctx context.Context, method, url string, payload any, check func(body []byte) error) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("%s marshal: %w", s.name, err)
	}
	respBody, err := s.SendRawReadBody(ctx, method, url, body, "application/json")
	if err != nil {
		return err
	}
	return check(respBody)
}

// SendRawReadBody sends bytes and returns the response body on success.
// For APIs where the response body contains per-item results (ES bulk).
func (s *Sender) SendRawReadBody(ctx context.Context, method, url string, body []byte, contentType string) ([]byte, error) {
	req, err := s.buildRequest(ctx, method, url, body, contentType)
	if err != nil {
		return nil, err
	}
	return s.DoReadBody(ctx, req)
}

// HealthCheck sends a GET request and returns an error if unreachable.
func (s *Sender) HealthCheck(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("%s healthcheck: %w", s.name, err)
	}
	return s.Do(ctx, req)
}

// Do executes a prepared request. Only 2xx is success.
func (s *Sender) Do(ctx context.Context, req *http.Request) error {
	resp, err := s.execute(req)
	if err != nil {
		return err
	}
	defer drain(resp)

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return fmt.Errorf("%s: HTTP %d: %s", s.name, resp.StatusCode, string(body))
	}
	return nil
}

// DoReadBody executes a request and returns the full response body on 2xx.
func (s *Sender) DoReadBody(ctx context.Context, req *http.Request) ([]byte, error) {
	resp, err := s.execute(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s read response: %w", s.name, err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s: HTTP %d: %s", s.name, resp.StatusCode, string(body))
	}
	return body, nil
}

// execute applies headers, auth, and runs the HTTP request.
func (s *Sender) execute(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", userAgent)
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	if s.basicUser != "" {
		req.SetBasicAuth(s.basicUser, s.basicPass)
	}

	resp, err := s.client.Do(req) //nolint:gosec // output URLs are user-configured
	if err != nil {
		return nil, fmt.Errorf("%s send: %w", s.name, err)
	}
	return resp, nil
}

// buildRequest creates an HTTP request with content type set.
func (s *Sender) buildRequest(ctx context.Context, method, url string, body []byte, contentType string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s request: %w", s.name, err)
	}
	req.Header.Set("Content-Type", contentType)
	return req, nil
}

func gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// drain reads the response body to EOF and closes it.
// Reading to EOF enables HTTP/1.1 keep-alive connection reuse.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
