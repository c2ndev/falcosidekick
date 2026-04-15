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

package inmemory

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func testEvent(rule string, priority event.Priority, source string, t time.Time) *event.Event {
	return &event.Event{
		UUID:         fmt.Sprintf("uuid-%s-%d", rule, t.UnixNano()),
		Output:       fmt.Sprintf("output for %s", rule),
		Priority:     priority,
		Rule:         rule,
		Time:         t,
		OutputFields: map[string]interface{}{"key": "value"},
		Source:       source,
		Tags:         []string{"tag1", "tag2"},
		Hostname:     "node-1",
	}
}

func createTestOutput(capacity int) *driver {
	o, _ := createOutput(map[string]any{
		"capacity":    capacity,
		"ttl":         "0s",
		"gc_interval": "10s",
	}, output.Deps{})
	return o.(*driver)
}

// --- OutputDriver compliance ---

func TestName(t *testing.T) {
	o := createTestOutput(100)
	assert.Equal(t, "inmemory", o.Name())
}

func TestInit(t *testing.T) {
	o := createTestOutput(100)
	assert.NoError(t, o.Init(context.Background()))
	assert.NoError(t, o.Close())
}

func TestHealthCheck(t *testing.T) {
	o := createTestOutput(100)
	assert.NoError(t, o.HealthCheck(context.Background()))
}

func TestCloseIsIdempotent(t *testing.T) {
	o := createTestOutput(100)
	require.NoError(t, o.Init(context.Background()))
	assert.NoError(t, o.Close())
	assert.NoError(t, o.Close(), "second Close must not panic or error")
}

// --- createOutput validation ---

func TestCreateRuntimeDefaults(t *testing.T) {
	o, err := createOutput(map[string]any{}, output.Deps{})
	require.NoError(t, err)
	mem := o.(*driver)
	assert.Equal(t, 10000, mem.capacity)
	assert.Equal(t, time.Duration(0), mem.ttl)
	assert.Equal(t, time.Duration(0), mem.gcInterval)
}

func TestCreateOutputCustomConfig(t *testing.T) {
	o, err := createOutput(map[string]any{
		"capacity":    500,
		"ttl":         "1h",
		"gc_interval": "30s",
	}, output.Deps{})
	require.NoError(t, err)
	mem := o.(*driver)
	assert.Equal(t, 500, mem.capacity)
	assert.Equal(t, time.Hour, mem.ttl)
	assert.Equal(t, 30*time.Second, mem.gcInterval)
}

// --- Send + ReadableStore ---

func TestSendAndSearch(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("rule-a", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("rule-b", event.PriorityError, "syscall", now.Add(time.Second))))

	result, err := o.Search(ctx, &output.SearchQuery{})
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.Total)
	assert.Len(t, result.Events, 2)
	assert.Equal(t, "rule-b", result.Events[0].Rule)
	assert.Equal(t, "rule-a", result.Events[1].Rule)
}

func TestSearchByPriority(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("low", event.PriorityDebug, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("mid", event.PriorityWarning, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("high", event.PriorityCritical, "syscall", now.Add(2*time.Second))))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{Priority: []string{"warning", "critical"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.Total)
	assert.Equal(t, "high", result.Events[0].Rule)
	assert.Equal(t, "mid", result.Events[1].Rule)
}

func TestSearchByRule(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("rule-a", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("rule-b", event.PriorityWarning, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("rule-c", event.PriorityWarning, "syscall", now.Add(2*time.Second))))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{Rule: []string{"rule-a", "rule-c"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.Total)
}

func TestSearchBySource(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("r1", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("r2", event.PriorityWarning, "k8s_audit", now.Add(time.Second))))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{Source: []string{"k8s_audit"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "r2", result.Events[0].Rule)
}

func TestSearchByHostname(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	e1 := testEvent("r1", event.PriorityWarning, "syscall", now)
	e1.Hostname = "node-1"
	e2 := testEvent("r2", event.PriorityWarning, "syscall", now.Add(time.Second))
	e2.Hostname = "node-2"

	require.NoError(t, o.Send(ctx, e1))
	require.NoError(t, o.Send(ctx, e2))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{Hostname: []string{"node-2"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "r2", result.Events[0].Rule)
}

func TestSearchByTags(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	e1 := testEvent("r1", event.PriorityWarning, "syscall", now)
	e1.Tags = []string{"filesystem", "mitre"}
	e2 := testEvent("r2", event.PriorityWarning, "syscall", now.Add(time.Second))
	e2.Tags = []string{"network", "dns"}

	require.NoError(t, o.Send(ctx, e1))
	require.NoError(t, o.Send(ctx, e2))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{Tags: []string{"network"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "r2", result.Events[0].Rule)
}

func TestSearchByTimeWindow(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	old := time.Now().Add(-2 * time.Hour)
	recent := time.Now().Add(-5 * time.Minute)

	require.NoError(t, o.Send(ctx, testEvent("old", event.PriorityWarning, "syscall", old)))
	require.NoError(t, o.Send(ctx, testEvent("recent", event.PriorityWarning, "syscall", recent)))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{Since: 1 * time.Hour},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "recent", result.Events[0].Rule)
}

func TestSearchFreeText(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	e1 := testEvent("Write below binary dir", event.PriorityError, "syscall", now)
	e1.Output = "File below /usr/bin opened for writing"
	e2 := testEvent("Shell spawned", event.PriorityWarning, "syscall", now.Add(time.Second))
	e2.Output = "Shell spawned in container"

	require.NoError(t, o.Send(ctx, e1))
	require.NoError(t, o.Send(ctx, e2))

	tests := []struct {
		name   string
		filter string
		want   int
	}{
		{"match output", "binary", 1},
		{"match rule", "Shell spawned", 1},
		{"match case insensitive", "BINARY", 1},
		{"no match", "nonexistent", 0},
		{"match both", "syscall", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := o.Search(ctx, &output.SearchQuery{Filter: tt.filter})
			require.NoError(t, err)
			assert.Equal(t, int64(tt.want), result.Total)
		})
	}
}

func TestSearchCombinedFilters(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("rule-a", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("rule-a", event.PriorityCritical, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("rule-b", event.PriorityWarning, "syscall", now.Add(2*time.Second))))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{
			Rule:     []string{"rule-a"},
			Priority: []string{"critical"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "rule-a", result.Events[0].Rule)
	assert.Equal(t, event.PriorityCritical, result.Events[0].Priority)
}

func TestSearchPagination(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	for i := 0; i < 25; i++ {
		require.NoError(t, o.Send(ctx, testEvent(
			fmt.Sprintf("rule-%02d", i), event.PriorityWarning, "syscall", now.Add(time.Duration(i)*time.Second),
		)))
	}

	tests := []struct {
		name      string
		page      int
		limit     int
		wantCount int
		wantTotal int64
	}{
		{"first page", 1, 10, 10, 25},
		{"second page", 2, 10, 10, 25},
		{"third page (partial)", 3, 10, 5, 25},
		{"beyond last page", 4, 10, 0, 25},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := o.Search(ctx, &output.SearchQuery{Page: tt.page, Limit: tt.limit})
			require.NoError(t, err)
			assert.Equal(t, tt.wantTotal, result.Total)
			assert.Len(t, result.Events, tt.wantCount)
			assert.Equal(t, tt.page, result.Page)
			assert.Equal(t, tt.limit, result.Limit)
		})
	}
}

func TestCapacityDropsOldest(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(3)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("first", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("second", event.PriorityWarning, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("third", event.PriorityWarning, "syscall", now.Add(2*time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("fourth", event.PriorityWarning, "syscall", now.Add(3*time.Second))))

	result, err := o.Search(ctx, &output.SearchQuery{})
	require.NoError(t, err)
	assert.Equal(t, int64(3), result.Total)

	rules := make([]string, len(result.Events))
	for i, e := range result.Events {
		rules[i] = e.Rule
	}
	assert.NotContains(t, rules, "first")
	assert.Contains(t, rules, "second")
	assert.Contains(t, rules, "third")
	assert.Contains(t, rules, "fourth")
}

func TestCount(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("r1", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("r2", event.PriorityError, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("r3", event.PriorityCritical, "k8s_audit", now.Add(2*time.Second))))

	tests := []struct {
		filters *output.Filters
		name    string
		want    int64
	}{
		{&output.Filters{}, "all", 3},
		{&output.Filters{Priority: []string{"warning"}}, "by priority", 1},
		{&output.Filters{Source: []string{"k8s_audit"}}, "by source", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, err := o.Count(ctx, tt.filters)
			require.NoError(t, err)
			assert.Equal(t, tt.want, count)
		})
	}
}

func TestCountBy(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("r1", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("r2", event.PriorityWarning, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("r3", event.PriorityCritical, "k8s_audit", now.Add(2*time.Second))))

	tests := []struct {
		want  map[string]int64
		name  string
		field string
	}{
		{map[string]int64{"warning": 2, "critical": 1}, "by priority", "priority"},
		{map[string]int64{"syscall": 2, "k8s_audit": 1}, "by source", "source"},
		{map[string]int64{"r1": 1, "r2": 1, "r3": 1}, "by rule", "rule"},
		{map[string]int64{"node-1": 3}, "by hostname", "hostname"},
		{map[string]int64{"tag1": 3, "tag2": 3}, "by tags", "tags"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := o.CountBy(ctx, tt.field, &output.Filters{})
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestCountByWithFilters(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("r1", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("r2", event.PriorityWarning, "k8s_audit", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("r3", event.PriorityCritical, "syscall", now.Add(2*time.Second))))

	result, err := o.CountBy(ctx, "priority", &output.Filters{Source: []string{"syscall"}})
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{"warning": 1, "critical": 1}, result)
}

func TestCountByInvalidField(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	_, err := o.CountBy(ctx, "invalid", &output.Filters{})
	assert.Error(t, err)
}

func TestEmptyStoreReturnsZero(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	result, err := o.Search(ctx, &output.SearchQuery{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.Total)
	assert.Empty(t, result.Events)

	count, err := o.Count(ctx, &output.Filters{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestTTLExpiry(t *testing.T) {
	ctx := context.Background()
	o, err := createOutput(map[string]any{
		"capacity":    100,
		"ttl":         "100ms",
		"gc_interval": "50ms",
	}, output.Deps{})
	require.NoError(t, err)

	mem := o.(*driver)
	require.NoError(t, mem.Init(ctx))
	defer mem.Close()

	require.NoError(t, mem.Send(ctx, testEvent("r1", event.PriorityWarning, "syscall", time.Now())))

	count, err := mem.Count(ctx, &output.Filters{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	time.Sleep(200 * time.Millisecond)

	count, err = mem.Count(ctx, &output.Filters{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(1000)

	done := make(chan struct{})

	go func() {
		for i := 0; i < 500; i++ {
			_ = o.Send(ctx, testEvent(
				fmt.Sprintf("rule-%d", i), event.PriorityWarning, "syscall", time.Now(),
			))
		}
		close(done)
	}()

	for i := 0; i < 100; i++ {
		_, _ = o.Search(ctx, &output.SearchQuery{})
		_, _ = o.Count(ctx, &output.Filters{})
		_, _ = o.CountBy(ctx, "priority", &output.Filters{})
	}

	<-done

	count, err := o.Count(ctx, &output.Filters{})
	require.NoError(t, err)
	assert.Equal(t, int64(500), count)
}

func TestSearchCombinedIndexIntersection(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("rule-a", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("rule-a", event.PriorityCritical, "k8s_audit", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("rule-b", event.PriorityWarning, "syscall", now.Add(2*time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("rule-b", event.PriorityCritical, "k8s_audit", now.Add(3*time.Second))))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{
			Rule:   []string{"rule-a"},
			Source: []string{"syscall"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "rule-a", result.Events[0].Rule)
	assert.Equal(t, "syscall", result.Events[0].Source)

	result, err = o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{
			Rule:     []string{"rule-b"},
			Priority: []string{"critical"},
			Source:   []string{"k8s_audit"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "rule-b", result.Events[0].Rule)
}

// --- Interface compliance ---

func TestImplementsOutputDriver(t *testing.T) {
	o := createTestOutput(10)
	var _ output.Driver = o
}

func TestImplementsReadableStore(t *testing.T) {
	o := createTestOutput(10)
	var _ output.ReadableStore = o
}

func TestSearchSortByRule(t *testing.T) {
	o := createTestOutput(100)
	now := time.Now()
	require.NoError(t, o.Send(context.Background(), testEvent("ZZZ_rule", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(context.Background(), testEvent("AAA_rule", event.PriorityError, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(context.Background(), testEvent("MMM_rule", event.PriorityNotice, "syscall", now.Add(2*time.Second))))

	result, err := o.Search(context.Background(), &output.SearchQuery{SortBy: "rule", SortDesc: false})
	require.NoError(t, err)
	require.Len(t, result.Events, 3)
	assert.Equal(t, "AAA_rule", result.Events[0].Rule)
	assert.Equal(t, "ZZZ_rule", result.Events[2].Rule)
}

func TestSearchSortByPriority(t *testing.T) {
	o := createTestOutput(100)
	now := time.Now()
	require.NoError(t, o.Send(context.Background(), testEvent("r1", event.PriorityDebug, "syscall", now)))
	require.NoError(t, o.Send(context.Background(), testEvent("r2", event.PriorityEmergency, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(context.Background(), testEvent("r3", event.PriorityWarning, "syscall", now.Add(2*time.Second))))

	result, err := o.Search(context.Background(), &output.SearchQuery{SortBy: "priority", SortDesc: true})
	require.NoError(t, err)
	require.Len(t, result.Events, 3)
	assert.Equal(t, event.PriorityEmergency, result.Events[0].Priority)
	assert.Equal(t, event.PriorityDebug, result.Events[2].Priority)
}

func TestSearchSortAscendingTimestamp(t *testing.T) {
	o := createTestOutput(100)
	now := time.Now()
	require.NoError(t, o.Send(context.Background(), testEvent("r3", event.PriorityWarning, "syscall", now.Add(2*time.Second))))
	require.NoError(t, o.Send(context.Background(), testEvent("r1", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(context.Background(), testEvent("r2", event.PriorityWarning, "syscall", now.Add(time.Second))))

	result, err := o.Search(context.Background(), &output.SearchQuery{SortBy: "timestamp", SortDesc: false})
	require.NoError(t, err)
	require.Len(t, result.Events, 3)
	assert.True(t, result.Events[0].Time.Before(result.Events[2].Time), "ascending: oldest first")
}
