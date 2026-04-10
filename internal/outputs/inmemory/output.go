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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mitchellh/mapstructure"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

func decodeConfig(raw map[string]any, result *config) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook:       mapstructure.StringToTimeDurationHookFunc(),
		WeaklyTypedInput: true,
		Result:           result,
	})
	if err != nil {
		return err
	}
	return decoder.Decode(raw)
}

const (
	fieldPriority = "priority"
	fieldRule     = "rule"
	fieldSource   = "source"
	fieldHostname = "hostname"
	fieldTags     = "tags"

	// Defaults.
	defaultCapacity   = 10000
	defaultTTL        = 24 * time.Hour
	defaultGCInterval = 10 * time.Second
)

// Type describes the in-memory event store for the output catalog.
var Type = domain.OutputType{
	New:      createOutput,
	Name:     "memory",
	Category: "store",
	Schema: domain.OutputSchema{
		Fields: []domain.SchemaField{
			{Name: "capacity", Type: "int", Default: 10000, Required: true, Label: "Max Events"},
			{Name: "ttl", Type: "string", Default: "24h", Label: "Event TTL"},
			{Name: "gc_interval", Type: "string", Default: "10s", Label: "GC Interval"},
		},
	},
}

type config struct {
	TTL        time.Duration `mapstructure:"ttl"`
	GCInterval time.Duration `mapstructure:"gc_interval"`
	Capacity   int           `mapstructure:"capacity"`
}

type output struct {
	byRule     map[string]map[int]struct{}
	byPriority map[string]map[int]struct{}
	bySource   map[string]map[int]struct{}
	byHostname map[string]map[int]struct{}
	byTag      map[string]map[int]struct{}
	stopGC     chan struct{}
	events     []*domain.Event
	ttl        time.Duration
	gcInterval time.Duration
	head       int
	count      int
	capacity   int
	mu         sync.RWMutex
}

func createOutput(raw map[string]any, _ domain.OutputDeps) (domain.OutputDriver, error) {
	var cfg config
	if err := decodeConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("memory config: %w", err)
	}
	if cfg.Capacity <= 0 {
		cfg.Capacity = defaultCapacity
	}
	if cfg.TTL < 0 {
		cfg.TTL = defaultTTL
	}
	if cfg.GCInterval <= 0 {
		cfg.GCInterval = defaultGCInterval
	}

	return &output{
		events:     make([]*domain.Event, cfg.Capacity),
		capacity:   cfg.Capacity,
		ttl:        cfg.TTL,
		gcInterval: cfg.GCInterval,
		byRule:     make(map[string]map[int]struct{}),
		byPriority: make(map[string]map[int]struct{}),
		bySource:   make(map[string]map[int]struct{}),
		byHostname: make(map[string]map[int]struct{}),
		byTag:      make(map[string]map[int]struct{}),
		stopGC:     make(chan struct{}),
	}, nil
}

func (o *output) Name() string { return "memory" }

func (o *output) Init(_ context.Context) error {
	if o.ttl > 0 {
		go o.runGC(o.gcInterval)
	}
	return nil
}

func (o *output) Send(_ context.Context, event *domain.Event) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	pos := o.head

	if o.events[pos] != nil {
		o.removeFromIndexes(pos)
	}

	o.events[pos] = event

	o.addToIndex(o.byRule, event.Rule, pos)
	o.addToIndex(o.byPriority, string(event.Priority), pos)
	o.addToIndex(o.bySource, event.Source, pos)
	if event.Hostname != "" {
		o.addToIndex(o.byHostname, event.Hostname, pos)
	}
	for _, tag := range event.Tags {
		o.addToIndex(o.byTag, tag, pos)
	}

	o.head = (o.head + 1) % o.capacity
	if o.count < o.capacity {
		o.count++
	}

	return nil
}

func (o *output) HealthCheck(_ context.Context) error { return nil }

func (o *output) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	select {
	case <-o.stopGC:
	default:
		close(o.stopGC)
	}
	return nil
}

// --- ReadableStore ---

func (o *output) Search(_ context.Context, query *domain.SearchQuery) (*domain.SearchResult, error) {
	if err := query.Normalize(); err != nil {
		return nil, err
	}

	o.mu.RLock()
	defer o.mu.RUnlock()

	candidates := o.findMatchingEvents(&query.Filters, query.Filter)

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

func (o *output) Count(_ context.Context, filters *domain.Filters) (int64, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return int64(len(o.findMatchingEvents(filters, ""))), nil
}

func (o *output) CountBy(_ context.Context, field string, filters *domain.Filters) (map[string]int64, error) {
	if err := domain.ValidateGroupBy(field); err != nil {
		return nil, err
	}

	o.mu.RLock()
	defer o.mu.RUnlock()

	if hasNoFilters(filters) {
		return o.countFromIndex(field), nil
	}

	return countFromEvents(o.findMatchingEvents(filters, ""), field), nil
}

// --- Internal methods ---

func (o *output) findMatchingEvents(filters *domain.Filters, freeText string) []*domain.Event {
	positions := o.findMatchingPositions(filters)

	var result []*domain.Event
	for pos := range positions {
		e := o.events[pos]
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

func (o *output) findMatchingPositions(filters *domain.Filters) map[int]struct{} {
	if hasNoStructuredFilters(filters) {
		return o.collectAllPositions()
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

	narrow(o.byPriority, filters.Priority)
	narrow(o.byRule, filters.Rule)
	narrow(o.bySource, filters.Source)
	narrow(o.byHostname, filters.Hostname)
	narrow(o.byTag, filters.Tags)

	if first {
		return o.collectAllPositions()
	}

	return result
}

func (o *output) collectAllPositions() map[int]struct{} {
	positions := make(map[int]struct{}, o.count)
	for i := 0; i < o.capacity; i++ {
		if o.events[i] != nil {
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

func (o *output) addToIndex(idx map[string]map[int]struct{}, key string, pos int) {
	if _, ok := idx[key]; !ok {
		idx[key] = make(map[int]struct{})
	}
	idx[key][pos] = struct{}{}
}

func (o *output) removeFromIndexes(pos int) {
	e := o.events[pos]
	if e == nil {
		return
	}
	removeFromIndex(o.byRule, e.Rule, pos)
	removeFromIndex(o.byPriority, string(e.Priority), pos)
	removeFromIndex(o.bySource, e.Source, pos)
	removeFromIndex(o.byHostname, e.Hostname, pos)
	for _, tag := range e.Tags {
		removeFromIndex(o.byTag, tag, pos)
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

func (o *output) countFromIndex(field string) map[string]int64 {
	var idx map[string]map[int]struct{}
	switch field {
	case fieldPriority:
		idx = o.byPriority
	case fieldRule:
		idx = o.byRule
	case fieldSource:
		idx = o.bySource
	case fieldHostname:
		idx = o.byHostname
	case fieldTags:
		idx = o.byTag
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

func (o *output) runGC(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-o.stopGC:
			return
		case <-ticker.C:
			o.removeExpired()
		}
	}
}

func (o *output) removeExpired() {
	o.mu.Lock()
	defer o.mu.Unlock()

	cutoff := time.Now().Add(-o.ttl)
	for i := 0; i < o.capacity; i++ {
		if o.events[i] != nil && o.events[i].Time.Before(cutoff) {
			o.removeFromIndexes(i)
			o.events[i] = nil
			o.count--
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
