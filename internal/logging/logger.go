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

package logging

import (
	"fmt"
	"log/slog"
	"os"

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

// ValidLogLevels holds the set of accepted log level values.
var ValidLogLevels = map[LogLevel]bool{
	TraceLevel: true, DebugLevel: true, InfoLevel: true, WarnLevel: true, ErrorLevel: true,
}

// Validate checks the log level for correctness.
func (l LogLevel) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if !ValidLogLevels[l] {
		errs.Add("log_level", fmt.Sprintf("must be trace/debug/info/warn/warning/error, got %q", l))
	}
	return errs
}

// LogFormat identifies a log output format.
type LogFormat string

// Supported log formats.
const (
	JSONFormat LogFormat = "json"
	TextFormat LogFormat = "text"
)

// ValidLogFormats holds the set of accepted log format values.
var ValidLogFormats = map[LogFormat]bool{
	TextFormat: true, JSONFormat: true,
}

// Validate checks the log format for correctness.
func (f LogFormat) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if !ValidLogFormats[f] {
		errs.Add("log_format", fmt.Sprintf("must be text/json, got %q", f))
	}
	return errs
}

// NewLogger creates a slog.Logger configured for the given level and format.
func NewLogger(level LogLevel, format LogFormat) (*slog.Logger, error) {
	slogLevel, err := parseLevel(string(level))
	if err != nil {
		return nil, err
	}

	opts := &slog.HandlerOptions{Level: slogLevel}

	var handler slog.Handler
	switch format {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	case "text":
		handler = slog.NewTextHandler(os.Stdout, opts)
	default:
		return nil, fmt.Errorf("logging: unsupported format %q", format)
	}

	return slog.New(handler), nil
}

func parseLevel(level string) (slog.Level, error) {
	switch level {
	case "trace":
		return slog.LevelDebug - 4, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("logging: unsupported level %q", level)
	}
}
