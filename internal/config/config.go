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

	"github.com/falcosecurity/falcosidekick/internal/logging"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// Config holds the complete falcosidekick configuration.
type Config struct {
	TLS           *TLSConfig        `mapstructure:"tls,omitempty"`
	LogFormat     logging.LogFormat `mapstructure:"log_format"`
	LogLevel      logging.LogLevel  `mapstructure:"log_level"`
	ListenAddress string            `mapstructure:"listen_address"`
	UI            UIConfig          `mapstructure:"ui"`
	Pipeline      PipelineConfig    `mapstructure:"pipeline"`
	ListenPort    int               `mapstructure:"listen_port"`
	Debug         bool              `mapstructure:"debug"`
}

// Validate checks the configuration for errors. Calls each sub-config's
// own Validate method. Returns all errors found.
func (cfg *Config) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors

	if cfg.ListenPort < 1 || cfg.ListenPort > 65535 {
		errs.Add("listen_port", fmt.Sprintf("must be 1-65535, got %d", cfg.ListenPort))
	}

	errs.Merge("", cfg.LogLevel.Validate())

	errs.Merge("", cfg.LogFormat.Validate())

	if cfg.TLS != nil {
		errs.Merge("tls", cfg.TLS.Validate())
	}

	errs.Merge("pipeline", cfg.Pipeline.Validate())

	errs.Merge("ui", cfg.UI.Validate())

	if len(errs) > 0 {
		return errs
	}
	return nil
}
