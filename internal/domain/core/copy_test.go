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

package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeepCopyWithTLS(t *testing.T) {
	original := &Config{
		ListenPort: 2801,
		TLS: &TLSConfig{
			CertFile: "/original/cert.pem",
			Enabled:  true,
		},
	}
	cp := original.DeepCopy()

	original.TLS.CertFile = "/mutated"
	assert.Equal(t, "/original/cert.pem", cp.TLS.CertFile, "DeepCopy must not alias TLS pointer")
}

func TestDeepCopyWithoutTLS(t *testing.T) {
	original := &Config{ListenPort: 2801}
	cp := original.DeepCopy()
	require.Nil(t, cp.TLS)
	assert.Equal(t, 2801, cp.ListenPort)
}

func TestDeepCopyDoesNotAliasScalars(t *testing.T) {
	original := &Config{ListenPort: 2801, LogLevel: LogLevelInfo}
	cp := original.DeepCopy()
	original.ListenPort = 9999
	assert.Equal(t, 2801, cp.ListenPort)
}
