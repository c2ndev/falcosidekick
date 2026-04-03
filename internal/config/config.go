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

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// LogLevel identifies a logging verbosity level.
type LogLevel string

// Supported log levels.
const (
	TraceLevel LogLevel = "trace"
	DebugLevel LogLevel = "debug"
	InfoLevel  LogLevel = "info"
	WarnLevel  LogLevel = "warning"
	ErrorLevel LogLevel = "error"
)

// LogFormat identifies a log output format.
type LogFormat string

// Supported log formats.
const (
	JSONFormat LogFormat = "json"
	TextFormat LogFormat = "text"
)

var validLogLevels = map[LogLevel]bool{
	TraceLevel: true, DebugLevel: true, InfoLevel: true, WarnLevel: true, ErrorLevel: true,
}

var validLogFormats = map[LogFormat]bool{
	TextFormat: true, JSONFormat: true,
}

// Config holds the complete falcosidekick configuration.
type Config struct {
	LogFormat     string           `mapstructure:"log_format"`
	LogLevel      string           `mapstructure:"log_level"`
	ListenAddress string           `mapstructure:"listen_address"`
	TLS           *TLSConfig       `mapstructure:"tls,omitempty"`
	EventStore    EventStoreConfig `mapstructure:"eventstore,omitempty"`
	Pipeline      PipelineConfig   `mapstructure:"pipeline"`
	ListenPort    int              `mapstructure:"listen_port"`
	UI            UISection        `mapstructure:"ui"`
	Debug         bool             `mapstructure:"debug"`
}

// Validate checks the configuration for errors. Calls each sub-config's
// own Validate method. Returns all errors found.
func (cfg *Config) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors

	if cfg.ListenPort < 1 || cfg.ListenPort > 65535 {
		errs.Add("listen_port", fmt.Sprintf("must be 1-65535, got %d", cfg.ListenPort))
	}

	if !validLogLevels[LogLevel(cfg.LogLevel)] {
		errs.Add("log_level", fmt.Sprintf("must be trace/debug/info/warn/warning/error, got %q", cfg.LogLevel))
	}

	if !validLogFormats[LogFormat(cfg.LogFormat)] {
		errs.Add("log_format", fmt.Sprintf("must be text/json, got %q", cfg.LogFormat))
	}

	if cfg.TLS != nil {
		errs.Merge("tls", cfg.TLS.Validate())
	}

	errs.Merge("eventstore", cfg.EventStore.Validate())
	errs.Merge("pipeline", cfg.Pipeline.Validate())

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// UISection holds UI settings.
type UISection struct {
	Enabled bool `mapstructure:"enabled"`
}
