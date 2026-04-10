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

package alertmanager

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/outputs/sdk"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestAlertmanagerCommonCases(t *testing.T) {
	testutil.RunOutputTests(t, Type, []testutil.OutputTestCase{
		{Name: "sends valid event", AddressField: "hosts", AddressSlice: true},
		{Name: "returns error on server 500", AddressField: "hosts", AddressSlice: true, MockStatus: http.StatusInternalServerError, ExpectError: true},
	})
}

func TestAlertmanagerPayloadFormat(t *testing.T) {
	testutil.RunOutputTests(t, Type, []testutil.OutputTestCase{
		{
			Name:         "sends alert with required fields",
			AddressField: "hosts",
			AddressSlice: true,
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var alerts []alertPayload
				require.NoError(t, json.Unmarshal(body, &alerts))
				require.Len(t, alerts, 1)
				assert.NotEmpty(t, alerts[0].Labels["alertname"], "must include alertname label")
				assert.NotEmpty(t, alerts[0].Labels["rule"])
				assert.NotEmpty(t, alerts[0].Labels["severity"])
				assert.NotEmpty(t, alerts[0].StartsAt, "must include startsAt")
				assert.NotEmpty(t, alerts[0].Annotations["info"])
			},
		},
		{
			Name:         "posts to v2 API endpoint by default",
			AddressField: "hosts",
			AddressSlice: true,
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				assert.Equal(t, "/api/v2/alerts", req.URL.Path)
			},
		},
		{
			Name:         "includes extra labels",
			AddressField: "hosts",
			AddressSlice: true,
			Config:       map[string]any{"extra_labels": map[string]string{"env": "prod"}},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var alerts []alertPayload
				require.NoError(t, json.Unmarshal(body, &alerts))
				assert.Equal(t, "prod", alerts[0].Labels["env"])
			},
		},
		{
			Name:         "sets endsAt when expires_after configured",
			AddressField: "hosts",
			AddressSlice: true,
			Config:       map[string]any{"expires_after": 300},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var alerts []alertPayload
				require.NoError(t, json.Unmarshal(body, &alerts))
				assert.NotEmpty(t, alerts[0].EndsAt)
			},
		},
		{
			Name:         "sets custom headers",
			AddressField: "hosts",
			AddressSlice: true,
			Config:       map[string]any{"headers": map[string]string{"X-Auth": "token123"}},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				assert.Equal(t, "token123", req.Header.Get("X-Auth"))
			},
		},
	})
}

func TestAlertmanagerCreateValidation(t *testing.T) {
	_, err := createOutput(map[string]any{}, domain.OutputDeps{})
	assert.Error(t, err, "missing hosts must fail")
}

func TestFanOutSendsToAllHosts(t *testing.T) {
	var count1, count2 atomic.Int32

	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count1.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count2.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server2.Close()

	o := &output{
		cfg:      config{Endpoint: defaultEndpoint},
		sender:   sdk.NewSender("alertmanager", &sdk.HTTPConfig{}),
		logger:   slog.Default().With("output", "alertmanager"),
		hostURLs: []string{server1.URL + defaultEndpoint, server2.URL + defaultEndpoint},
	}

	err := o.Send(context.Background(), testutil.CreateValidEvent())
	require.NoError(t, err)
	assert.Equal(t, int32(1), count1.Load(), "host 1 must receive the alert")
	assert.Equal(t, int32(1), count2.Load(), "host 2 must receive the alert")
}

func TestFanOutSucceedsIfOneHostWorks(t *testing.T) {
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("down"))
	}))
	defer badServer.Close()

	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer goodServer.Close()

	o := &output{
		cfg:      config{Endpoint: defaultEndpoint},
		sender:   sdk.NewSender("alertmanager", &sdk.HTTPConfig{}),
		logger:   slog.Default().With("output", "alertmanager"),
		hostURLs: []string{badServer.URL + defaultEndpoint, goodServer.URL + defaultEndpoint},
	}

	err := o.Send(context.Background(), testutil.CreateValidEvent())
	assert.NoError(t, err, "must succeed when at least one host works")
}

func TestFanOutFailsWhenAllHostsFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("down"))
	}))
	defer server.Close()

	o := &output{
		cfg:      config{Endpoint: defaultEndpoint},
		sender:   sdk.NewSender("alertmanager", &sdk.HTTPConfig{}),
		logger:   slog.Default().With("output", "alertmanager"),
		hostURLs: []string{server.URL + defaultEndpoint, server.URL + defaultEndpoint},
	}

	err := o.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all 2 hosts failed")
}

func TestSingleHostSkipsFanOut(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	o := &output{
		cfg:      config{Endpoint: defaultEndpoint},
		sender:   sdk.NewSender("alertmanager", &sdk.HTTPConfig{}),
		logger:   slog.Default().With("output", "alertmanager"),
		hostURLs: []string{server.URL + defaultEndpoint},
	}

	require.NoError(t, o.Send(context.Background(), testutil.CreateValidEvent()))
	assert.Equal(t, int32(1), callCount.Load())
}

func TestAlertmanagerHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/-/healthy", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	o := &output{
		cfg:      config{Endpoint: defaultEndpoint},
		sender:   sdk.NewSender("alertmanager", &sdk.HTTPConfig{}),
		logger:   slog.Default().With("output", "alertmanager"),
		hostURLs: []string{server.URL + defaultEndpoint},
	}

	assert.NoError(t, o.HealthCheck(context.Background()))
}

func TestAlertmanagerHealthCheckNoHosts(t *testing.T) {
	o := &output{cfg: config{}}
	assert.Error(t, o.HealthCheck(context.Background()))
}

func TestAlertmanagerCustomEndpoint(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"hosts":    []string{"http://am:9093"},
		"endpoint": "/api/v2/alerts",
	}, domain.OutputDeps{})
	require.NoError(t, err)

	o := driver.(*output)
	assert.Equal(t, "http://am:9093/api/v2/alerts", o.hostURLs[0])
}

func TestAlertmanagerInit(t *testing.T) {
	o := &output{}
	assert.NoError(t, o.Init(context.Background()))
}

func TestAlertmanagerClose(t *testing.T) {
	o := &output{}
	assert.NoError(t, o.Close())
}
