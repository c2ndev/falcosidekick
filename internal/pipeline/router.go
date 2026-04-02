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

package pipeline

import "github.com/falcosecurity/falcosidekick/internal/domain"

// Router determines which outputs receive an event based on priority filtering.
type Router struct {
	outputPriorities map[string]domain.Priority
}

// NewRouter creates a Router with per-output minimum priority thresholds.
func NewRouter(outputPriorities map[string]domain.Priority) *Router {
	return &Router{outputPriorities: outputPriorities}
}

// RouteEvent returns the names of outputs that should receive the event.
func (r *Router) RouteEvent(event *domain.Event) []string {
	var targets []string
	for outputName, minPriority := range r.outputPriorities {
		if event.Priority.GTE(minPriority) {
			targets = append(targets, outputName)
		}
	}
	return targets
}
