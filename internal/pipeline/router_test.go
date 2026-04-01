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

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

func TestRouteEventByPriority(t *testing.T) {
	r := NewRouter(map[string]domain.Priority{
		"slack":         domain.PriorityWarning,
		"elasticsearch": domain.PriorityDebug,
		"pagerduty":     domain.PriorityCritical,
	})

	tests := []struct {
		name     string
		priority domain.Priority
		want     []string
	}{
		{
			name:     "critical reaches all",
			priority: domain.PriorityCritical,
			want:     []string{"elasticsearch", "pagerduty", "slack"},
		},
		{
			name:     "warning reaches slack and elasticsearch",
			priority: domain.PriorityWarning,
			want:     []string{"elasticsearch", "slack"},
		},
		{
			name:     "debug reaches only elasticsearch",
			priority: domain.PriorityDebug,
			want:     []string{"elasticsearch"},
		},
		{
			name:     "informational below warning skips slack",
			priority: domain.PriorityInformational,
			want:     []string{"elasticsearch"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &domain.Event{
				Rule:     "Some rule",
				Priority: tt.priority,
			}
			got := r.RouteEvent(event)
			sort.Strings(got)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRouteEventEmptyPriorityPassesAll(t *testing.T) {
	r := NewRouter(map[string]domain.Priority{
		"loki": domain.Priority(""),
	})

	event := &domain.Event{
		Rule:     "Some rule",
		Priority: domain.PriorityDebug,
	}

	got := r.RouteEvent(event)
	assert.Equal(t, []string{"loki"}, got)
}

func TestRouteEventNoOutputs(t *testing.T) {
	r := NewRouter(map[string]domain.Priority{})

	event := &domain.Event{
		Rule:     "Some rule",
		Priority: domain.PriorityCritical,
	}

	got := r.RouteEvent(event)
	assert.Empty(t, got)
}

func TestRouteEventEqualPriorityPasses(t *testing.T) {
	r := NewRouter(map[string]domain.Priority{
		"slack": domain.PriorityWarning,
	})

	event := &domain.Event{
		Rule:     "Some rule",
		Priority: domain.PriorityWarning,
	}

	got := r.RouteEvent(event)
	assert.Equal(t, []string{"slack"}, got)
}
