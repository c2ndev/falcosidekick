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
	"fmt"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

// ServerConfig holds HTTP server dependencies.
type ServerConfig struct {
	Pipeline  *pipeline.Pipeline
	ReadStore domain.ReadableStore
	Metrics   domain.MetricsCollector
	Registry  *prometheus.Registry
	Address   string
	Port      int
}

// Server manages the Fiber HTTP application.
type Server struct {
	app       *fiber.App
	pipeline  *pipeline.Pipeline
	readStore domain.ReadableStore
	metrics   domain.MetricsCollector
	address   string
}

// NewServer creates a Fiber-based HTTP Server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Pipeline == nil {
		return nil, fmt.Errorf("server: pipeline is required")
	}
	if cfg.Address == "" {
		cfg.Address = "0.0.0.0"
	}
	if cfg.Port <= 0 {
		cfg.Port = 2801
	}

	s := &Server{
		pipeline:  cfg.Pipeline,
		readStore: cfg.ReadStore,
		metrics:   cfg.Metrics,
		address:   fmt.Sprintf("%s:%d", cfg.Address, cfg.Port),
	}

	app := fiber.New()

	app.Use(recover.New())

	app.Post("/", s.handlePostEvent)
	app.Get("/healthz", s.handleGetHealthz)

	if cfg.Registry != nil {
		handler := promhttp.HandlerFor(cfg.Registry, promhttp.HandlerOpts{})
		app.Get("/metrics", adaptor.HTTPHandler(handler))
	}

	s.app = app
	return s, nil
}

// Start begins listening for HTTP requests. Blocks until the server stops.
func (s *Server) Start() error {
	return s.app.Listen(s.address)
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown() error {
	return s.app.Shutdown()
}
