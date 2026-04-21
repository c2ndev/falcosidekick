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

package api

import (
	"github.com/gofiber/fiber/v3"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

func (s *Server) handlePipelineStatus(c fiber.Ctx) error {
	statuses := s.pipeline.CollectOutputStatus()
	if statuses == nil {
		statuses = []pipeline.OutputStatus{}
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"outputs": statuses})
}

func (s *Server) handlePipelineStatusByName(c fiber.Ctx) error {
	name := c.Params("name")
	for _, st := range s.pipeline.CollectOutputStatus() {
		if st.Name == name {
			return c.Status(fiber.StatusOK).JSON(st)
		}
	}
	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "output not found"})
}

func (s *Server) handlePipelineOutputs(c fiber.Ctx) error {
	entries, ok := s.loadMaskedOutputs(c)
	if !ok {
		return nil
	}
	return c.Status(fiber.StatusOK).JSON(entries)
}

func (s *Server) handlePipelineOutputByName(c fiber.Ctx) error {
	if s.database == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "database not configured"})
	}
	name := c.Params("name")
	entry, err := s.database.GetOutputConfig(c.Context(), name)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "read output: " + err.Error()})
	}
	if entry == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "output not found"})
	}
	t, _ := s.catalog.Get(name)
	masked := maskOutputConfig(*entry, t)
	return c.Status(fiber.StatusOK).JSON(masked)
}

func (s *Server) handlePipelineOutputTypes(c fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"types": s.catalog.All()})
}

func (s *Server) handlePipelineOutputTypeByName(c fiber.Ctx) error {
	name := c.Params("name")
	t, ok := s.catalog.Get(name)
	if !ok {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "output type not found"})
	}
	return c.Status(fiber.StatusOK).JSON(t)
}

func (s *Server) handlePipelineLayout(c fiber.Ctx) error {
	if s.database == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "database not configured"})
	}
	layout, err := s.database.GetPipelineLayout(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	if layout == nil {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{})
	}
	return c.Status(fiber.StatusOK).JSON(layout)
}

func (s *Server) handlePipelineComposite(c fiber.Ctx) error {
	outputs, ok := s.loadMaskedOutputs(c)
	if !ok {
		return nil
	}

	statuses := s.pipeline.CollectOutputStatus()
	if statuses == nil {
		statuses = []pipeline.OutputStatus{}
	}

	layout, err := s.database.GetPipelineLayout(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "read layout: " + err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"outputs": outputs,
		"status":  statuses,
		"layout":  layout,
	})
}

// loadMaskedOutputs writes 503/500 and returns (nil, false) when the
// database is nil or fails; caller must return nil.
func (s *Server) loadMaskedOutputs(c fiber.Ctx) (map[string]core.OutputConfigEntry, bool) {
	if s.database == nil {
		_ = c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "database not configured"})
		return nil, false
	}
	entries, err := s.database.GetOutputConfigs(c.Context())
	if err != nil {
		_ = c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "read outputs: " + err.Error()})
		return nil, false
	}
	return maskOutputConfigs(entries, s.catalog), true
}
