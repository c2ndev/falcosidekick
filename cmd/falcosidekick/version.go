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

package main

import "runtime"

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
	goVersion = runtime.Version()
)

// VersionInfo holds build-time version metadata.
type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
}

// GetVersionInfo returns the current build version metadata.
func GetVersionInfo() VersionInfo {
	return VersionInfo{
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
		GoVersion: goVersion,
	}
}
