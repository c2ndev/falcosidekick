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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildTLSConfigDefaults(t *testing.T) {
	cfg, err := BuildTLSConfig(&TLSConfig{})
	require.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.False(t, cfg.InsecureSkipVerify)
	assert.Nil(t, cfg.RootCAs)
	assert.Empty(t, cfg.Certificates)
}

func TestBuildTLSConfigInsecure(t *testing.T) {
	cfg, err := BuildTLSConfig(&TLSConfig{InsecureSkipVerify: true})
	require.NoError(t, err)
	assert.True(t, cfg.InsecureSkipVerify)
}

func TestBuildTLSConfigServerName(t *testing.T) {
	cfg, err := BuildTLSConfig(&TLSConfig{ServerName: "kafka.example.com"})
	require.NoError(t, err)
	assert.Equal(t, "kafka.example.com", cfg.ServerName)
}

func TestBuildTLSConfigInvalidCAFile(t *testing.T) {
	_, err := BuildTLSConfig(&TLSConfig{CAFile: "/nonexistent/ca.pem"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read CA file")
}

func TestBuildTLSConfigInvalidCertKey(t *testing.T) {
	_, err := BuildTLSConfig(&TLSConfig{CertFile: "/nonexistent/cert.pem", KeyFile: "/nonexistent/key.pem"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load client cert/key")
}
