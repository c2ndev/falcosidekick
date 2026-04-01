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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

const (
	fieldPriority = "priority"
	fieldRule     = "rule"
	fieldSource   = "source"
	fieldHostname = "hostname"
	fieldTags     = "tags"
)

// MemoryStore implements domain.EventStore with a ring buffer,
// secondary indexes, and TTL-based expiry.
type MemoryStore struct {
	byRule     map[string]map[int]struct{}
	byPriority map[string]map[int]struct{}
	bySource   map[string]map[int]struct{}
	byHostname map[string]map[int]struct{}
	byTag      map[string]map[int]struct{}
	stopGC     chan struct{}
	events     []*domain.Event
	ttl        time.Duration
	head       int
	count      int
	capacity   int
	mu         sync.RWMutex
}

// MemoryConfig holds MemoryStore settings.
type MemoryConfig struct {
	Capacity   int
	TTL        time.Duration
	GCInterval time.Duration
}

// NewMemoryStore creates an in-memory EventStore.
func NewMemoryStore(cfg MemoryConfig) *MemoryStore {
	if cfg.Capacity <= 0 {
		cfg.Capacity = 10000
	}
	if cfg.GCInterval <= 0 {
		cfg.GCInterval = 10 * time.Second
	}

	s := &MemoryStore{
		events:     make([]*domain.Event, cfg.Capacity),
		capacity:   cfg.Capacity,
		ttl:        cfg.TTL,
		byRule:     make(map[string]map[int]struct{}),
		byPriority: make(map[string]map[int]struct{}),
		bySource:   make(map[string]map[int]struct{}),
		byHostname: make(map[string]map[int]struct{}),
		byTag:      make(map[string]map[int]struct{}),
		stopGC:     make(chan struct{}),
	}

	if cfg.TTL > 0 {
		go s.runGC(cfg.GCInterval)
	}

	return s
}

// Append stores an event. Overwrites the oldest event when at capacity.
func (s *MemoryStore) Append(_ context.Context, event *domain.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pos := s.head

	if s.events[pos] != nil {
		s.removeFromIndexes(pos)
	}

	s.events[pos] = event

	s.addToIndex(s.byRule, event.Rule, pos)
	s.addToIndex(s.byPriority, string(event.Priority), pos)
	s.addToIndex(s.bySource, event.Source, pos)
	if event.Hostname != "" {
		s.addToIndex(s.byHostname, event.Hostname, pos)
	}
	for _, tag := range event.Tags {
		s.addToIndex(s.byTag, tag, pos)
	}

	s.head = (s.head + 1) % s.capacity
	if s.count < s.capacity {
		s.count++
	}

	return nil
}

// Search returns events matching the query, sorted by timestamp descending.
func (s *MemoryStore) Search(_ context.Context, query *domain.SearchQuery) (*domain.SearchResult, error) {
	if err := query.Normalize(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	candidates := s.findMatchingEvents(&query.Filters, query.Filter)

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Time.After(candidates[j].Time)
	})

	total := int64(len(candidates))
	offset := (query.Page - 1) * query.Limit
	if offset >= len(candidates) {
		return &domain.SearchResult{
			Events: []domain.Event{}, Total: total,
			Page: query.Page, Limit: query.Limit,
		}, nil
	}

	end := offset + query.Limit
	if end > len(candidates) {
		end = len(candidates)
	}

	page := make([]domain.Event, 0, end-offset)
	for _, e := range candidates[offset:end] {
		page = append(page, *e)
	}

	return &domain.SearchResult{
		Events: page, Total: total,
		Page: query.Page, Limit: query.Limit,
	}, nil
}

// Count returns the total number of events matching the filters.
func (s *MemoryStore) Count(_ context.Context, filters *domain.Filters) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.findMatchingEvents(filters, ""))), nil
}

// CountBy returns event counts grouped by the specified field.
func (s *MemoryStore) CountBy(_ context.Context, field string, filters *domain.Filters) (map[string]int64, error) {
	if err := domain.ValidateGroupBy(field); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if hasNoFilters(filters) {
		return s.countFromIndex(field), nil
	}

	return countFromEvents(s.findMatchingEvents(filters, ""), field), nil
}

// Close stops the GC goroutine. Safe to call multiple times.
func (s *MemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.stopGC:
	default:
		close(s.stopGC)
	}
	return nil
}

func (s *MemoryStore) findMatchingEvents(filters *domain.Filters, freeText string) []*domain.Event {
	positions := s.findMatchingPositions(filters)

	var result []*domain.Event
	for pos := range positions {
		e := s.events[pos]
		if e == nil {
			continue
		}
		if filters.Since > 0 && e.Time.Before(time.Now().Add(-filters.Since)) {
			continue
		}
		if freeText != "" && !matchesFreeText(e, freeText) {
			continue
		}
		result = append(result, e)
	}

	return result
}

// findMatchingPositions intersects index lookups per filter field (AND between fields, OR within).
func (s *MemoryStore) findMatchingPositions(filters *domain.Filters) map[int]struct{} {
	if hasNoStructuredFilters(filters) {
		return s.collectAllPositions()
	}

	var result map[int]struct{}
	first := true

	narrow := func(index map[string]map[int]struct{}, values []string) {
		if len(values) == 0 {
			return
		}
		union := collectUnion(index, values)
		if first {
			result = union
			first = false
		} else {
			result = intersectSets(result, union)
		}
	}

	narrow(s.byPriority, filters.Priority)
	narrow(s.byRule, filters.Rule)
	narrow(s.bySource, filters.Source)
	narrow(s.byHostname, filters.Hostname)
	narrow(s.byTag, filters.Tags)

	if first {
		return s.collectAllPositions()
	}

	return result
}

func (s *MemoryStore) collectAllPositions() map[int]struct{} {
	positions := make(map[int]struct{}, s.count)
	for i := 0; i < s.capacity; i++ {
		if s.events[i] != nil {
			positions[i] = struct{}{}
		}
	}
	return positions
}

func collectUnion(index map[string]map[int]struct{}, values []string) map[int]struct{} {
	result := make(map[int]struct{})
	for _, v := range values {
		for pos := range index[v] {
			result[pos] = struct{}{}
		}
	}
	return result
}

func intersectSets(a, b map[int]struct{}) map[int]struct{} {
	if len(a) > len(b) {
		a, b = b, a
	}
	result := make(map[int]struct{}, len(a))
	for pos := range a {
		if _, ok := b[pos]; ok {
			result[pos] = struct{}{}
		}
	}
	return result
}

func (s *MemoryStore) addToIndex(idx map[string]map[int]struct{}, key string, pos int) {
	if _, ok := idx[key]; !ok {
		idx[key] = make(map[int]struct{})
	}
	idx[key][pos] = struct{}{}
}

func (s *MemoryStore) removeFromIndexes(pos int) {
	e := s.events[pos]
	if e == nil {
		return
	}
	removeFromIndex(s.byRule, e.Rule, pos)
	removeFromIndex(s.byPriority, string(e.Priority), pos)
	removeFromIndex(s.bySource, e.Source, pos)
	removeFromIndex(s.byHostname, e.Hostname, pos)
	for _, tag := range e.Tags {
		removeFromIndex(s.byTag, tag, pos)
	}
}

func removeFromIndex(idx map[string]map[int]struct{}, key string, pos int) {
	if set, ok := idx[key]; ok {
		delete(set, pos)
		if len(set) == 0 {
			delete(idx, key)
		}
	}
}

func (s *MemoryStore) countFromIndex(field string) map[string]int64 {
	var idx map[string]map[int]struct{}
	switch field {
	case fieldPriority:
		idx = s.byPriority
	case fieldRule:
		idx = s.byRule
	case fieldSource:
		idx = s.bySource
	case fieldHostname:
		idx = s.byHostname
	case fieldTags:
		idx = s.byTag
	}

	result := make(map[string]int64, len(idx))
	for key, positions := range idx {
		result[key] = int64(len(positions))
	}
	return result
}

func countFromEvents(events []*domain.Event, field string) map[string]int64 {
	result := make(map[string]int64)
	for _, e := range events {
		switch field {
		case fieldPriority:
			result[string(e.Priority)]++
		case fieldRule:
			result[e.Rule]++
		case fieldSource:
			result[e.Source]++
		case fieldHostname:
			result[e.Hostname]++
		case fieldTags:
			for _, tag := range e.Tags {
				result[tag]++
			}
		}
	}
	return result
}

func (s *MemoryStore) runGC(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopGC:
			return
		case <-ticker.C:
			s.removeExpired()
		}
	}
}

func (s *MemoryStore) removeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-s.ttl)
	for i := 0; i < s.capacity; i++ {
		if s.events[i] != nil && s.events[i].Time.Before(cutoff) {
			s.removeFromIndexes(i)
			s.events[i] = nil
			s.count--
		}
	}
}

func hasNoFilters(f *domain.Filters) bool {
	return len(f.Priority) == 0 && len(f.Rule) == 0 && len(f.Source) == 0 &&
		len(f.Hostname) == 0 && len(f.Tags) == 0 && f.Since == 0
}

func hasNoStructuredFilters(f *domain.Filters) bool {
	return len(f.Priority) == 0 && len(f.Rule) == 0 && len(f.Source) == 0 &&
		len(f.Hostname) == 0 && len(f.Tags) == 0
}

func matchesFreeText(e *domain.Event, text string) bool {
	lower := strings.ToLower(text)
	for _, field := range []string{e.Output, e.Rule, string(e.Priority), e.Source, e.Hostname} {
		if strings.Contains(strings.ToLower(field), lower) {
			return true
		}
	}
	for _, tag := range e.Tags {
		if strings.Contains(strings.ToLower(tag), lower) {
			return true
		}
	}
	return false
}
