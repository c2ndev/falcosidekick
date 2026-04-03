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

package config

import (
	"fmt"
	"os"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// TLSConfig holds server and client TLS settings.
type TLSConfig struct {
	Server TLSServerConfig `mapstructure:"server"`
	Client TLSClientConfig `mapstructure:"client"`
}

// TLSServerConfig holds server-side TLS settings.
type TLSServerConfig struct {
	CertFile   string `mapstructure:"certfile"`
	KeyFile    string `mapstructure:"keyfile"`
	CACertFile string `mapstructure:"cacertfile"`
	Enabled    bool   `mapstructure:"enabled"`
	MutualTLS  bool   `mapstructure:"mutualtls"`
}

// TLSClientConfig holds client-side TLS settings.
type TLSClientConfig struct {
	CertFile   string `mapstructure:"certfile"`
	KeyFile    string `mapstructure:"keyfile"`
	CACertFile string `mapstructure:"cacertfile"`
	MutualTLS  bool   `mapstructure:"mutualtls"`
}

// Validate checks TLS settings for errors.
func (tls *TLSConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("server", tls.Server.Validate())
	errs.Merge("client", tls.Client.Validate())
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// Validate checks server TLS settings.
func (ts *TLSServerConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if ts.Enabled {
		if ts.CertFile == "" {
			errs.Add("certfile", "must be specified when TLS is enabled")
		} else if _, err := os.Stat(ts.CertFile); err != nil {
			errs.Add("certfile", fmt.Sprintf("file does not exist: %v", err))
		}
		if ts.KeyFile == "" {
			errs.Add("keyfile", "must be specified when TLS is enabled")
		} else if _, err := os.Stat(ts.KeyFile); err != nil {
			errs.Add("keyfile", fmt.Sprintf("file does not exist: %v", err))
		}
		if ts.MutualTLS {
			if ts.CACertFile == "" {
				errs.Add("cacertfile", "must be specified when mutual TLS is enabled")
			} else if _, err := os.Stat(ts.CACertFile); err != nil {
				errs.Add("cacertfile", fmt.Sprintf("file does not exist: %v", err))
			}
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// Validate checks client TLS settings.
func (tc *TLSClientConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if tc.MutualTLS {
		if tc.CertFile == "" {
			errs.Add("certfile", "must be specified when mutual TLS is enabled")
		} else if _, err := os.Stat(tc.CertFile); err != nil {
			errs.Add("certfile", fmt.Sprintf("file does not exist: %v", err))
		}
		if tc.KeyFile == "" {
			errs.Add("keyfile", "must be specified when mutual TLS is enabled")
		} else if _, err := os.Stat(tc.KeyFile); err != nil {
			errs.Add("keyfile", fmt.Sprintf("file does not exist: %v", err))
		}
		if tc.CACertFile == "" {
			errs.Add("cacertfile", "must be specified when mutual TLS is enabled")
		} else if _, err := os.Stat(tc.CACertFile); err != nil {
			errs.Add("cacertfile", fmt.Sprintf("file does not exist: %v", err))
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}
