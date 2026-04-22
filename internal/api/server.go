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
	"context"
	"fmt"
	"io/fs"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

// ServerConfig holds HTTP server dependencies.
type ServerConfig struct {
	Pipeline    *pipeline.Pipeline
	Database    core.Database
	Catalog     *catalog.Catalog
	Metrics     core.MetricsCollector
	Registry    *prometheus.Registry
	TLS         *core.TLSConfig
	UIAssets    fs.FS // optional; serves under GET / when non-nil
	Address     string
	EventSource string // output name implementing ReadableStore; resolved dynamically via Pipeline
	Port        int
}

// Server manages the Fiber HTTP application.
type Server struct {
	app         *fiber.App
	pipeline    *pipeline.Pipeline
	database    core.Database
	catalog     *catalog.Catalog
	metrics     core.MetricsCollector
	tls         *core.TLSConfig
	uiAssets    fs.FS
	address     string
	eventSource string
}

// NewServer creates a Fiber-based HTTP Server.
func NewServer(cfg *ServerConfig) (*Server, error) {
	if cfg.Pipeline == nil {
		return nil, fmt.Errorf("server: pipeline is required")
	}
	if cfg.Catalog == nil {
		return nil, fmt.Errorf("server: catalog is required")
	}
	if cfg.Address == "" {
		cfg.Address = "0.0.0.0"
	}
	if cfg.Port <= 0 {
		cfg.Port = 2801
	}

	s := &Server{
		pipeline:    cfg.Pipeline,
		database:    cfg.Database,
		catalog:     cfg.Catalog,
		metrics:     cfg.Metrics,
		tls:         cfg.TLS,
		uiAssets:    cfg.UIAssets,
		address:     fmt.Sprintf("%s:%d", cfg.Address, cfg.Port),
		eventSource: cfg.EventSource,
	}

	s.app = s.mountRoutes(cfg.Registry)
	return s, nil
}

// mountRoutes registers routes with static segments (`/types`, `/status`,
// `/layout`) declared before `:name` so Fiber's matcher prefers literals.
func (s *Server) mountRoutes(registry *prometheus.Registry) *fiber.App {
	app := fiber.New()
	app.Use(recover.New())

	app.Post("/", s.handlePostEvent)
	app.Get("/healthz", s.handleGetHealthz)
	app.Get("/version", s.handleGetVersion)

	v1 := app.Group("/api/v1")

	events := v1.Group("/events")
	events.Get("/search", s.handleEventsSearch)
	events.Get("/count", s.handleEventsCount)
	events.Get("/count/:groupby", s.handleEventsCountBy)
	events.Get("/:uuid", s.handleEventByUUID)

	pipe := v1.Group("/pipeline")
	pipe.Get("", s.handlePipelineComposite)
	pipe.Get("/layout", s.handlePipelineLayout)
	pipe.Get("/status", s.handlePipelineStatus)
	pipe.Get("/status/:name", s.handlePipelineStatusByName)

	outputs := pipe.Group("/outputs")
	outputs.Get("", s.handlePipelineOutputs)
	outputs.Get("/types", s.handlePipelineOutputTypes)
	outputs.Get("/types/:name", s.handlePipelineOutputTypeByName)
	outputs.Get("/:name", s.handlePipelineOutputByName)

	v1.Get("/config", s.handleGetConfig)
	v1.Get("/version", s.handleGetVersion)

	if registry != nil {
		handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		app.Get("/metrics", adaptor.HTTPHandler(handler))
	}

	registerStaticUI(app, s.uiAssets)

	return app
}

// GetReadableStore resolves the ReadableStore dynamically through the pipeline.
// Returns nil when no event source is configured or the output does not implement ReadableStore.
func (s *Server) GetReadableStore() output.ReadableStore {
	if s.eventSource == "" {
		return nil
	}
	rs, _ := s.pipeline.GetReadableStore(s.eventSource)
	return rs
}

// Start begins listening for HTTP requests. Blocks until the server stops.
// Uses TLS when configured, including mutual TLS with client cert verification.
func (s *Server) Start() error {
	cfg := fiber.ListenConfig{DisableStartupMessage: true}
	if s.tls != nil && s.tls.Enabled {
		cfg.CertFile = s.tls.CertFile
		cfg.CertKeyFile = s.tls.KeyFile
		if s.tls.MutualTLS {
			cfg.CertClientFile = s.tls.CACertFile
		}
	}
	return s.app.Listen(s.address, cfg)
}

// Shutdown gracefully stops the server, bounded by the caller's context.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.app.ShutdownWithContext(ctx)
}
