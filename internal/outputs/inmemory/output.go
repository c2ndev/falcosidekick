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
	"sync"
	"time"

	"github.com/mitchellh/mapstructure"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
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

	defaultCapacity   = 10000
	defaultGCInterval = 10 * time.Second
)

// OutputType describes the in-memory event store for the output catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     "inmemory",
	Category: "store",
	Schema: output.Schema{
		Fields: []output.SchemaField{
			{Name: "capacity", Type: "int", Default: 10000, Required: true, Label: "Max Events"},
			{Name: "ttl", Type: "string", Default: "0", Label: "Event TTL (0 = no expiry)"},
			{Name: "gc_interval", Type: "string", Default: "10s", Label: "GC Interval (when TTL > 0)"},
		},
	},
}

type config struct {
	TTL        time.Duration `mapstructure:"ttl"`
	GCInterval time.Duration `mapstructure:"gc_interval"`
	Capacity   int           `mapstructure:"capacity"`
}

// driver implements a bounded ring buffer with optional TTL-based GC.
//
// Ring buffer invariants:
//   - head: next write position (advances on each Send)
//   - tail: oldest valid position (advances on overwrite or GC)
//   - count: number of valid events (always == occupied slots, no holes)
//   - When count < capacity: buffer has free slots, tail stays fixed
//   - When count == capacity: buffer full, writing at head overwrites tail
//   - GC only advances tail forward (never creates holes in the middle)
type driver struct {
	byRule     map[string]map[int]struct{}
	byPriority map[string]map[int]struct{}
	bySource   map[string]map[int]struct{}
	byHostname map[string]map[int]struct{}
	byTag      map[string]map[int]struct{}
	stopGC     chan struct{}
	events     []*event.Event
	ttl        time.Duration
	gcInterval time.Duration
	head       int
	tail       int
	count      int
	capacity   int
	mu         sync.RWMutex
}

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.Capacity == 0 {
		c.Capacity = defaultCapacity
	} else if c.Capacity < 0 {
		errs.Add("capacity", fmt.Sprintf("must be > 0, got %d", c.Capacity))
	}
	if c.TTL < 0 {
		errs.Add("ttl", fmt.Sprintf("must be >= 0 (0 = no expiry), got %v", c.TTL))
	}
	if c.TTL > 0 && c.GCInterval == 0 {
		c.GCInterval = defaultGCInterval
	}
	if c.GCInterval < 0 {
		errs.Add("gc_interval", fmt.Sprintf("must be >= 0, got %v", c.GCInterval))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, _ output.Deps) (output.Driver, error) {
	var cfg config
	if err := decodeConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("inmemory config: %w", err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("inmemory: %s", errs.Error())
	}

	return &driver{
		events:     make([]*event.Event, cfg.Capacity),
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

func (d *driver) Name() string { return "inmemory" }

func (d *driver) Init(_ context.Context) error {
	if d.ttl > 0 {
		go d.runGC(d.gcInterval)
	}
	return nil
}

// Send appends an event to the ring buffer.
// When full, overwrites the oldest event at head (which equals tail) and advances tail.
func (d *driver) Send(_ context.Context, evt *event.Event) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.count == d.capacity {
		d.removeFromIndexes(d.head)
		d.tail = (d.tail + 1) % d.capacity
	} else {
		d.count++
	}

	d.events[d.head] = evt
	d.addToIndexes(d.head, evt)
	d.head = (d.head + 1) % d.capacity

	return nil
}

func (d *driver) HealthCheck(_ context.Context) error { return nil }

func (d *driver) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-d.stopGC:
	default:
		close(d.stopGC)
	}
	return nil
}

// --- ReadableStore ---

func (d *driver) Search(_ context.Context, query *output.SearchQuery) (*output.SearchResult, error) {
	if err := query.Normalize(); err != nil {
		return nil, err
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	candidates := d.findMatchingEvents(&query.Filters, query.Filter)

	sortEvents(candidates, query.SortBy, query.SortDesc)

	total := int64(len(candidates))
	offset := (query.Page - 1) * query.Limit
	if offset >= len(candidates) {
		return &output.SearchResult{
			Events: []event.Event{}, Total: total,
			Page: query.Page, Limit: query.Limit,
		}, nil
	}

	end := offset + query.Limit
	if end > len(candidates) {
		end = len(candidates)
	}

	page := make([]event.Event, 0, end-offset)
	for _, e := range candidates[offset:end] {
		page = append(page, *e)
	}

	return &output.SearchResult{
		Events: page, Total: total,
		Page: query.Page, Limit: query.Limit,
	}, nil
}

func (d *driver) Count(_ context.Context, filters *output.Filters) (int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return int64(len(d.findMatchingEvents(filters, ""))), nil
}

func (d *driver) CountBy(_ context.Context, field string, filters *output.Filters) (map[string]int64, error) {
	if err := output.ValidateGroupBy(field); err != nil {
		return nil, err
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	if hasNoFilters(filters) {
		return d.countFromIndex(field), nil
	}

	return countFromEvents(d.findMatchingEvents(filters, ""), field), nil
}

// --- Ring buffer internals ---

func (d *driver) addToIndexes(pos int, evt *event.Event) {
	addToIndex(d.byRule, evt.Rule, pos)
	addToIndex(d.byPriority, string(evt.Priority), pos)
	addToIndex(d.bySource, evt.Source, pos)
	if evt.Hostname != "" {
		addToIndex(d.byHostname, evt.Hostname, pos)
	}
	for _, tag := range evt.Tags {
		addToIndex(d.byTag, tag, pos)
	}
}

func (d *driver) removeFromIndexes(pos int) {
	e := d.events[pos]
	if e == nil {
		return
	}
	removeFromIndex(d.byRule, e.Rule, pos)
	removeFromIndex(d.byPriority, string(e.Priority), pos)
	removeFromIndex(d.bySource, e.Source, pos)
	removeFromIndex(d.byHostname, e.Hostname, pos)
	for _, tag := range e.Tags {
		removeFromIndex(d.byTag, tag, pos)
	}
}

func addToIndex(idx map[string]map[int]struct{}, key string, pos int) {
	if _, ok := idx[key]; !ok {
		idx[key] = make(map[int]struct{})
	}
	idx[key][pos] = struct{}{}
}

func removeFromIndex(idx map[string]map[int]struct{}, key string, pos int) {
	if set, ok := idx[key]; ok {
		delete(set, pos)
		if len(set) == 0 {
			delete(idx, key)
		}
	}
}

// --- Query internals ---

func (d *driver) findMatchingEvents(filters *output.Filters, freeText string) []*event.Event {
	positions := d.findMatchingPositions(filters)

	var result []*event.Event
	for pos := range positions {
		e := d.events[pos]
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

func (d *driver) findMatchingPositions(filters *output.Filters) map[int]struct{} {
	if hasNoStructuredFilters(filters) {
		return d.collectAllPositions()
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

	narrow(d.byPriority, filters.Priority)
	narrow(d.byRule, filters.Rule)
	narrow(d.bySource, filters.Source)
	narrow(d.byHostname, filters.Hostname)
	narrow(d.byTag, filters.Tags)

	if first {
		return d.collectAllPositions()
	}

	return result
}

func (d *driver) collectAllPositions() map[int]struct{} {
	positions := make(map[int]struct{}, d.count)
	for i := 0; i < d.count; i++ {
		pos := (d.tail + i) % d.capacity
		positions[pos] = struct{}{}
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

func (d *driver) countFromIndex(field string) map[string]int64 {
	var idx map[string]map[int]struct{}
	switch field {
	case fieldPriority:
		idx = d.byPriority
	case fieldRule:
		idx = d.byRule
	case fieldSource:
		idx = d.bySource
	case fieldHostname:
		idx = d.byHostname
	case fieldTags:
		idx = d.byTag
	}

	result := make(map[string]int64, len(idx))
	for key, positions := range idx {
		result[key] = int64(len(positions))
	}
	return result
}

func countFromEvents(events []*event.Event, field string) map[string]int64 {
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

// --- GC ---

func (d *driver) runGC(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopGC:
			return
		case <-ticker.C:
			d.removeExpired()
		}
	}
}

// removeExpired advances tail past expired events.
// Only removes from the oldest end - never creates holes.
func (d *driver) removeExpired() {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().Add(-d.ttl)
	for d.count > 0 {
		e := d.events[d.tail]
		if e == nil || !e.Time.Before(cutoff) {
			break
		}
		d.removeFromIndexes(d.tail)
		d.events[d.tail] = nil
		d.tail = (d.tail + 1) % d.capacity
		d.count--
	}
}
