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

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

func testEvent(rule string, priority domain.Priority, source string, t time.Time) *domain.Event {
	return &domain.Event{
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

func newTestStore(capacity int) *MemoryStore {
	return NewMemoryStore(&MemoryConfig{
		Capacity:   capacity,
		GCInterval: 10 * time.Second,
	})
}

func TestAppendAndSearch(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(100)
	defer s.Close()

	now := time.Now()
	require.NoError(t, s.Append(ctx, testEvent("rule-a", domain.PriorityWarning, "syscall", now)))
	require.NoError(t, s.Append(ctx, testEvent("rule-b", domain.PriorityError, "syscall", now.Add(time.Second))))

	result, err := s.Search(ctx, &domain.SearchQuery{})
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.Total)
	assert.Len(t, result.Events, 2)
	// Newest first
	assert.Equal(t, "rule-b", result.Events[0].Rule)
	assert.Equal(t, "rule-a", result.Events[1].Rule)
}

func TestSearchByPriority(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(100)
	defer s.Close()

	now := time.Now()
	require.NoError(t, s.Append(ctx, testEvent("low", domain.PriorityDebug, "syscall", now)))
	require.NoError(t, s.Append(ctx, testEvent("mid", domain.PriorityWarning, "syscall", now.Add(time.Second))))
	require.NoError(t, s.Append(ctx, testEvent("high", domain.PriorityCritical, "syscall", now.Add(2*time.Second))))

	result, err := s.Search(ctx, &domain.SearchQuery{
		Filters: domain.Filters{Priority: []string{"warning", "critical"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.Total)
	assert.Equal(t, "high", result.Events[0].Rule)
	assert.Equal(t, "mid", result.Events[1].Rule)
}

func TestSearchByRule(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(100)
	defer s.Close()

	now := time.Now()
	require.NoError(t, s.Append(ctx, testEvent("rule-a", domain.PriorityWarning, "syscall", now)))
	require.NoError(t, s.Append(ctx, testEvent("rule-b", domain.PriorityWarning, "syscall", now.Add(time.Second))))
	require.NoError(t, s.Append(ctx, testEvent("rule-c", domain.PriorityWarning, "syscall", now.Add(2*time.Second))))

	result, err := s.Search(ctx, &domain.SearchQuery{
		Filters: domain.Filters{Rule: []string{"rule-a", "rule-c"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.Total)
}

func TestSearchBySource(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(100)
	defer s.Close()

	now := time.Now()
	require.NoError(t, s.Append(ctx, testEvent("r1", domain.PriorityWarning, "syscall", now)))
	require.NoError(t, s.Append(ctx, testEvent("r2", domain.PriorityWarning, "k8s_audit", now.Add(time.Second))))

	result, err := s.Search(ctx, &domain.SearchQuery{
		Filters: domain.Filters{Source: []string{"k8s_audit"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "r2", result.Events[0].Rule)
}

func TestSearchByHostname(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(100)
	defer s.Close()

	now := time.Now()
	e1 := testEvent("r1", domain.PriorityWarning, "syscall", now)
	e1.Hostname = "node-1"
	e2 := testEvent("r2", domain.PriorityWarning, "syscall", now.Add(time.Second))
	e2.Hostname = "node-2"

	require.NoError(t, s.Append(ctx, e1))
	require.NoError(t, s.Append(ctx, e2))

	result, err := s.Search(ctx, &domain.SearchQuery{
		Filters: domain.Filters{Hostname: []string{"node-2"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "r2", result.Events[0].Rule)
}

func TestSearchByTags(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(100)
	defer s.Close()

	now := time.Now()
	e1 := testEvent("r1", domain.PriorityWarning, "syscall", now)
	e1.Tags = []string{"filesystem", "mitre"}
	e2 := testEvent("r2", domain.PriorityWarning, "syscall", now.Add(time.Second))
	e2.Tags = []string{"network", "dns"}

	require.NoError(t, s.Append(ctx, e1))
	require.NoError(t, s.Append(ctx, e2))

	result, err := s.Search(ctx, &domain.SearchQuery{
		Filters: domain.Filters{Tags: []string{"network"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "r2", result.Events[0].Rule)
}

func TestSearchByTimeWindow(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(100)
	defer s.Close()

	old := time.Now().Add(-2 * time.Hour)
	recent := time.Now().Add(-5 * time.Minute)

	require.NoError(t, s.Append(ctx, testEvent("old", domain.PriorityWarning, "syscall", old)))
	require.NoError(t, s.Append(ctx, testEvent("recent", domain.PriorityWarning, "syscall", recent)))

	result, err := s.Search(ctx, &domain.SearchQuery{
		Filters: domain.Filters{Since: 1 * time.Hour},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "recent", result.Events[0].Rule)
}

func TestSearchFreeText(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(100)
	defer s.Close()

	now := time.Now()
	e1 := testEvent("Write below binary dir", domain.PriorityError, "syscall", now)
	e1.Output = "File below /usr/bin opened for writing"
	e2 := testEvent("Shell spawned", domain.PriorityWarning, "syscall", now.Add(time.Second))
	e2.Output = "Shell spawned in container"

	require.NoError(t, s.Append(ctx, e1))
	require.NoError(t, s.Append(ctx, e2))

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
			result, err := s.Search(ctx, &domain.SearchQuery{Filter: tt.filter})
			require.NoError(t, err)
			assert.Equal(t, int64(tt.want), result.Total)
		})
	}
}

func TestSearchCombinedFilters(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(100)
	defer s.Close()

	now := time.Now()
	require.NoError(t, s.Append(ctx, testEvent("rule-a", domain.PriorityWarning, "syscall", now)))
	require.NoError(t, s.Append(ctx, testEvent("rule-a", domain.PriorityCritical, "syscall", now.Add(time.Second))))
	require.NoError(t, s.Append(ctx, testEvent("rule-b", domain.PriorityWarning, "syscall", now.Add(2*time.Second))))

	result, err := s.Search(ctx, &domain.SearchQuery{
		Filters: domain.Filters{
			Rule:     []string{"rule-a"},
			Priority: []string{"critical"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "rule-a", result.Events[0].Rule)
	assert.Equal(t, domain.PriorityCritical, result.Events[0].Priority)
}

func TestSearchPagination(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(100)
	defer s.Close()

	now := time.Now()
	for i := 0; i < 25; i++ {
		require.NoError(t, s.Append(ctx, testEvent(
			fmt.Sprintf("rule-%02d", i), domain.PriorityWarning, "syscall", now.Add(time.Duration(i)*time.Second),
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
			result, err := s.Search(ctx, &domain.SearchQuery{Page: tt.page, Limit: tt.limit})
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
	s := newTestStore(3) // small capacity
	defer s.Close()

	now := time.Now()
	require.NoError(t, s.Append(ctx, testEvent("first", domain.PriorityWarning, "syscall", now)))
	require.NoError(t, s.Append(ctx, testEvent("second", domain.PriorityWarning, "syscall", now.Add(time.Second))))
	require.NoError(t, s.Append(ctx, testEvent("third", domain.PriorityWarning, "syscall", now.Add(2*time.Second))))
	// This overwrites "first"
	require.NoError(t, s.Append(ctx, testEvent("fourth", domain.PriorityWarning, "syscall", now.Add(3*time.Second))))

	result, err := s.Search(ctx, &domain.SearchQuery{})
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
	s := newTestStore(100)
	defer s.Close()

	now := time.Now()
	require.NoError(t, s.Append(ctx, testEvent("r1", domain.PriorityWarning, "syscall", now)))
	require.NoError(t, s.Append(ctx, testEvent("r2", domain.PriorityError, "syscall", now.Add(time.Second))))
	require.NoError(t, s.Append(ctx, testEvent("r3", domain.PriorityCritical, "k8s_audit", now.Add(2*time.Second))))

	tests := []struct {
		filters *domain.Filters
		name    string
		want    int64
	}{
		{&domain.Filters{}, "all", 3},
		{&domain.Filters{Priority: []string{"warning"}}, "by priority", 1},
		{&domain.Filters{Source: []string{"k8s_audit"}}, "by source", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, err := s.Count(ctx, tt.filters)
			require.NoError(t, err)
			assert.Equal(t, tt.want, count)
		})
	}
}

func TestCountBy(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(100)
	defer s.Close()

	now := time.Now()
	require.NoError(t, s.Append(ctx, testEvent("r1", domain.PriorityWarning, "syscall", now)))
	require.NoError(t, s.Append(ctx, testEvent("r2", domain.PriorityWarning, "syscall", now.Add(time.Second))))
	require.NoError(t, s.Append(ctx, testEvent("r3", domain.PriorityCritical, "k8s_audit", now.Add(2*time.Second))))

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
			result, err := s.CountBy(ctx, tt.field, &domain.Filters{})
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestCountByWithFilters(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(100)
	defer s.Close()

	now := time.Now()
	require.NoError(t, s.Append(ctx, testEvent("r1", domain.PriorityWarning, "syscall", now)))
	require.NoError(t, s.Append(ctx, testEvent("r2", domain.PriorityWarning, "k8s_audit", now.Add(time.Second))))
	require.NoError(t, s.Append(ctx, testEvent("r3", domain.PriorityCritical, "syscall", now.Add(2*time.Second))))

	// CountBy priority, but only for syscall source (filtered slow path)
	result, err := s.CountBy(ctx, "priority", &domain.Filters{Source: []string{"syscall"}})
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{"warning": 1, "critical": 1}, result)
}

func TestSearchCombinedIndexIntersection(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(100)
	defer s.Close()

	now := time.Now()
	require.NoError(t, s.Append(ctx, testEvent("rule-a", domain.PriorityWarning, "syscall", now)))
	require.NoError(t, s.Append(ctx, testEvent("rule-a", domain.PriorityCritical, "k8s_audit", now.Add(time.Second))))
	require.NoError(t, s.Append(ctx, testEvent("rule-b", domain.PriorityWarning, "syscall", now.Add(2*time.Second))))
	require.NoError(t, s.Append(ctx, testEvent("rule-b", domain.PriorityCritical, "k8s_audit", now.Add(3*time.Second))))

	// Two filters -> intersection of two index lookups
	// rule-a AND syscall -> only the first event
	result, err := s.Search(ctx, &domain.SearchQuery{
		Filters: domain.Filters{
			Rule:   []string{"rule-a"},
			Source: []string{"syscall"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "rule-a", result.Events[0].Rule)
	assert.Equal(t, "syscall", result.Events[0].Source)

	// Three filters -> triple intersection
	// rule-b AND critical AND k8s_audit -> only the fourth event
	result, err = s.Search(ctx, &domain.SearchQuery{
		Filters: domain.Filters{
			Rule:     []string{"rule-b"},
			Priority: []string{"critical"},
			Source:   []string{"k8s_audit"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "rule-b", result.Events[0].Rule)
}

func TestCountByInvalidField(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(100)
	defer s.Close()

	_, err := s.CountBy(ctx, "invalid", &domain.Filters{})
	assert.Error(t, err)
}

func TestEmptyStoreReturnsZero(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(100)
	defer s.Close()

	result, err := s.Search(ctx, &domain.SearchQuery{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.Total)
	assert.Empty(t, result.Events)

	count, err := s.Count(ctx, &domain.Filters{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestTTLExpiry(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(&MemoryConfig{
		Capacity:   100,
		TTL:        100 * time.Millisecond,
		GCInterval: 50 * time.Millisecond,
	})
	defer s.Close()

	require.NoError(t, s.Append(ctx, testEvent("r1", domain.PriorityWarning, "syscall", time.Now())))

	// Event exists immediately
	count, err := s.Count(ctx, &domain.Filters{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Wait for TTL + GC cycle
	time.Sleep(200 * time.Millisecond)

	count, err = s.Count(ctx, &domain.Filters{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestCloseIsIdempotent(t *testing.T) {
	s := newTestStore(100)
	assert.NoError(t, s.Close())
	assert.NoError(t, s.Close(), "second Close must not panic or error")
}

func TestMemoryConfigValidateValid(t *testing.T) {
	cfg := &MemoryConfig{Capacity: 1000, TTL: time.Hour, GCInterval: 10 * time.Second}
	assert.Empty(t, cfg.Validate())
}

func TestMemoryConfigValidateInvalid(t *testing.T) {
	tests := []struct {
		name string
		cfg  MemoryConfig
	}{
		{"zero capacity", MemoryConfig{Capacity: 0}},
		{"negative capacity", MemoryConfig{Capacity: -1}},
		{"negative ttl", MemoryConfig{Capacity: 100, TTL: -1}},
		{"negative gc_interval", MemoryConfig{Capacity: 100, GCInterval: -1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, tt.cfg.Validate())
		})
	}
}

func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(1000)
	defer s.Close()

	done := make(chan struct{})

	// Writer
	go func() {
		for i := 0; i < 500; i++ {
			_ = s.Append(ctx, testEvent(
				fmt.Sprintf("rule-%d", i), domain.PriorityWarning, "syscall", time.Now(),
			))
		}
		close(done)
	}()

	// Reader (concurrent with writer)
	for i := 0; i < 100; i++ {
		_, _ = s.Search(ctx, &domain.SearchQuery{})
		_, _ = s.Count(ctx, &domain.Filters{})
		_, _ = s.CountBy(ctx, "priority", &domain.Filters{})
	}

	<-done

	// Verify final state is consistent
	count, err := s.Count(ctx, &domain.Filters{})
	require.NoError(t, err)
	assert.Equal(t, int64(500), count)
}
