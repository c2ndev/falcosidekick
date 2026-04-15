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

package database

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
)

// Memory implements domain.Database with in-memory maps.
// All data is lost on restart and re-provisioned from files.
type Memory struct {
	outputs    map[string]core.OutputConfigEntry
	coreConfig *core.ConfigEntry
	layout     *core.PipelineLayout
	mu         sync.RWMutex
}

// NewMemory creates a memory-backed Database.
func NewMemory() *Memory {
	return &Memory{
		outputs: make(map[string]core.OutputConfigEntry),
	}
}

// Provision upserts file-sourced configs and removes stale provisioned entries.
func (s *Memory) Provision(_ context.Context, req *core.ProvisionRequest) error {
	if req == nil {
		return fmt.Errorf("database: provision request is nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	if req.Config != nil {
		ver := int64(1)
		if s.coreConfig != nil {
			ver = s.coreConfig.Version + 1
		}
		s.coreConfig = &core.ConfigEntry{
			Config:    req.Config.DeepCopy(),
			Version:   ver,
			UpdatedAt: now,
		}
	}

	for name, entry := range s.outputs {
		if entry.Provisioned {
			if _, exists := req.Outputs[name]; !exists {
				delete(s.outputs, name)
			}
		}
	}

	for name, cfg := range req.Outputs {
		ver := int64(1)
		if existing, ok := s.outputs[name]; ok {
			ver = existing.Version + 1
		}
		s.outputs[name] = core.OutputConfigEntry{
			Name:        name,
			Config:      deepCopyMap(cfg),
			Version:     ver,
			Provisioned: true,
			UpdatedAt:   now,
		}
	}

	return nil
}

// GetConfig returns the stored core configuration.
func (s *Memory) GetConfig(_ context.Context) (*core.ConfigEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.coreConfig == nil {
		return nil, nil
	}
	entry := *s.coreConfig
	if entry.Config != nil {
		entry.Config = entry.Config.DeepCopy()
	}
	return &entry, nil
}

// SaveConfig persists the core configuration.
func (s *Memory) SaveConfig(_ context.Context, cfg *core.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ver := int64(1)
	if s.coreConfig != nil {
		ver = s.coreConfig.Version + 1
	}
	s.coreConfig = &core.ConfigEntry{
		Config:    cfg.DeepCopy(),
		Version:   ver,
		UpdatedAt: time.Now(),
	}
	return nil
}

// GetOutputConfigs returns a defensive copy of all output entries.
func (s *Memory) GetOutputConfigs(_ context.Context) (map[string]core.OutputConfigEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]core.OutputConfigEntry, len(s.outputs))
	for k, v := range s.outputs {
		v.Config = deepCopyMap(v.Config)
		result[k] = v
	}
	return result, nil
}

// GetOutputConfig returns a single output entry by name.
func (s *Memory) GetOutputConfig(_ context.Context, name string) (*core.OutputConfigEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.outputs[name]
	if !ok {
		return nil, fmt.Errorf("database: output %q not found", name)
	}
	entry.Config = deepCopyMap(entry.Config)
	return &entry, nil
}

// SaveOutputConfig persists one output entry as non-provisioned.
func (s *Memory) SaveOutputConfig(_ context.Context, name string, cfg map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ver := int64(1)
	if existing, ok := s.outputs[name]; ok {
		ver = existing.Version + 1
	}
	s.outputs[name] = core.OutputConfigEntry{
		Name:        name,
		Config:      deepCopyMap(cfg),
		Version:     ver,
		Provisioned: false,
		UpdatedAt:   time.Now(),
	}
	return nil
}

// DeleteOutputConfig removes one output entry.
func (s *Memory) DeleteOutputConfig(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.outputs[name]; !ok {
		return fmt.Errorf("database: output %q not found", name)
	}
	delete(s.outputs, name)
	return nil
}

// GetPipelineLayout returns the stored pipeline layout or nil.
func (s *Memory) GetPipelineLayout(_ context.Context) (*core.PipelineLayout, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.layout == nil {
		return nil, nil
	}
	cp := *s.layout
	return &cp, nil
}

// SavePipelineLayout persists the UI pipeline node positions.
func (s *Memory) SavePipelineLayout(_ context.Context, layout *core.PipelineLayout) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *layout
	cp.UpdatedAt = time.Now()
	cp.Nodes = make([]core.LayoutNode, len(layout.Nodes))
	copy(cp.Nodes, layout.Nodes)
	s.layout = &cp
	return nil
}

// Close releases resources. No-op for the memory backend.
func (s *Memory) Close() error {
	return nil
}
