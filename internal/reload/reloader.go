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

package reload

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/config"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// ReloaderConfig holds the dependencies the Reloader needs. Long-lived
// contexts are not stored here; they are passed explicitly to Reload.
type ReloaderConfig struct {
	Deps            output.Deps
	Database        core.Database
	Registry        prometheus.Registerer
	Catalog         *catalog.Catalog
	Dispatcher      *pipeline.Dispatcher
	Logger          *slog.Logger
	InitialOutputs  map[string]map[string]any
	OutputPaths     []string
	RuntimeDefaults output.RuntimeConfig
}

// Reloader applies output config changes to a running dispatcher.
// Concurrent Reload calls are serialized by an internal mutex.
type Reloader struct {
	deps            output.Deps
	database        core.Database
	catalog         *catalog.Catalog
	dispatcher      *pipeline.Dispatcher
	metrics         *reloadMetrics
	current         map[string]map[string]any
	logger          *slog.Logger
	outputPaths     []string
	runtimeDefaults output.RuntimeConfig
	mu              sync.Mutex
}

// NewReloader returns a Reloader. InitialOutputs is deep-copied so the
// reloader's diff state is isolated from the caller.
func NewReloader(cfg *ReloaderConfig) *Reloader {
	return &Reloader{
		outputPaths:     cfg.OutputPaths,
		catalog:         cfg.Catalog,
		dispatcher:      cfg.Dispatcher,
		database:        cfg.Database,
		runtimeDefaults: cfg.RuntimeDefaults,
		deps:            cfg.Deps,
		metrics:         newReloadMetrics(cfg.Registry),
		current:         deepCopyOutputConfigs(cfg.InitialOutputs),
		logger:          cfg.Logger,
	}
}

func deepCopyOutputConfigs(src map[string]map[string]any) map[string]map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]map[string]any, len(src))
	for name, cfg := range src {
		dst[name] = utils.DeepCopyMap(cfg)
	}
	return dst
}

// Reload diffs the current output config files against the running state
// and applies the delta. On any pre-apply failure the running state is
// left unchanged.
//
// ctx bounds parse, Init, and DB Provision; typically derived from the
// process context. workerRunCtx is attached to new output workers so
// they outlive ctx cancellation during a clean shutdown. retireTimeout
// bounds retirement of old outputs only.
func (r *Reloader) Reload(ctx, workerRunCtx context.Context, retireTimeout time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	start := time.Now()

	outsCfg, err := config.LoadOutputs(r.outputPaths)
	if err != nil {
		r.metrics.recordFailure(time.Since(start))
		return fmt.Errorf("reload parse: %w", err)
	}

	for name := range outsCfg.Outputs {
		if _, ok := r.catalog.Get(name); !ok {
			r.metrics.recordFailure(time.Since(start))
			return fmt.Errorf("reload validate: unknown output type %q", name)
		}
	}

	for name, outputCfg := range outsCfg.Outputs {
		outputType, _ := r.catalog.Get(name) // validated above
		if err := config.ResolveSecrets(name, outputCfg, outputType.Schema); err != nil {
			r.metrics.recordFailure(time.Since(start))
			return fmt.Errorf("reload secrets: %w", err)
		}
	}

	diff := DiffOutputConfigs(r.current, outsCfg.Outputs)
	if diff.IsEmpty() {
		r.logger.Debug("reload: no output config changes detected")
		r.metrics.total.Inc() // no-op is still a reload attempt
		return nil
	}

	addedOutputs, err := r.createOutputs(ctx, diff.Added)
	if err != nil {
		r.metrics.recordFailure(time.Since(start))
		return fmt.Errorf("reload create added: %w", err)
	}

	changedOutputs, err := r.createOutputs(ctx, diff.Changed)
	if err != nil {
		closeOutputs(addedOutputs)
		r.metrics.recordFailure(time.Since(start))
		return fmt.Errorf("reload create changed: %w", err)
	}

	retireCtx, retireCancel := context.WithTimeout(ctx, retireTimeout)
	defer retireCancel()

	// stopped means the dispatcher rejected a mutation (shutdown in progress);
	// retireWarning means a drain timed out but the replacement is live.
	var stopped bool
	var retireWarning bool

	for _, out := range addedOutputs {
		if err := r.dispatcher.AddOutput(workerRunCtx, out); err != nil {
			if errors.Is(err, pipeline.ErrDispatcherStopped) {
				_ = out.Close()
				stopped = true
				r.logger.Warn("reload: add rejected, dispatcher stopped", "output", out.Name())
			}
		}
	}
	for name, out := range changedOutputs {
		if err := r.dispatcher.ReplaceOutput(retireCtx, workerRunCtx, name, out); err != nil {
			if errors.Is(err, pipeline.ErrDispatcherStopped) {
				_ = out.Close()
				stopped = true
				r.logger.Warn("reload: replace rejected, dispatcher stopped", "output", name)
			} else {
				retireWarning = true
				r.logger.Warn("reload: old output retire timeout, replacement active", "output", name, "error", err)
			}
		}
	}
	for _, name := range diff.Removed {
		if err := r.dispatcher.RemoveOutput(retireCtx, name); err != nil {
			if errors.Is(err, pipeline.ErrDispatcherStopped) {
				stopped = true
				r.logger.Warn("reload: remove rejected, dispatcher stopped", "output", name)
			} else {
				retireWarning = true
				r.logger.Warn("reload: removed output retire timeout", "output", name, "error", err)
			}
		}
	}

	if stopped {
		r.metrics.recordFailure(time.Since(start))
		return fmt.Errorf("reload abandoned: dispatcher stopped during apply")
	}

	var dbSyncFailed bool
	if r.database != nil {
		if err := r.database.Provision(ctx, &core.ProvisionRequest{
			Outputs: outsCfg.Outputs,
		}); err != nil {
			dbSyncFailed = true
			r.logger.Error("reload: database re-provision failed", "error", err)
		}
	}

	// Runtime apply succeeded past this point, so r.current always advances
	// regardless of DB sync or retire-timeout outcome.
	r.current = outsCfg.Outputs
	duration := time.Since(start)

	if retireWarning || dbSyncFailed {
		r.metrics.recordPartialSuccess(duration)
		r.logger.Warn("reload partial",
			"added", len(diff.Added),
			"changed", len(diff.Changed),
			"removed", len(diff.Removed),
			"retire_warning", retireWarning,
			"db_sync_failed", dbSyncFailed,
			"duration", duration,
		)
	} else {
		r.metrics.recordSuccess(duration)
		r.logger.Info("reload complete",
			"added", len(diff.Added),
			"changed", len(diff.Changed),
			"removed", len(diff.Removed),
			"duration", duration,
		)
	}
	return nil
}

// createOutputs builds the given set of outputs. On failure, outputs built
// so far in the batch are closed before returning.
func (r *Reloader) createOutputs(ctx context.Context, configs map[string]map[string]any) (map[string]*pipeline.Output, error) {
	outputs := make(map[string]*pipeline.Output, len(configs))

	for name, cfg := range configs {
		driver, err := r.catalog.Create(name, cfg, r.deps)
		if err != nil {
			closeOutputs(outputs)
			return nil, fmt.Errorf("output %q create: %w", name, err)
		}

		if err := driver.Init(ctx); err != nil {
			_ = driver.Close()
			closeOutputs(outputs)
			return nil, fmt.Errorf("output %q init: %w", name, err)
		}

		merged, err := config.MergeRuntimeConfig(r.runtimeDefaults, name, driver.RuntimeConfig())
		if err != nil {
			_ = driver.Close()
			closeOutputs(outputs)
			return nil, fmt.Errorf("output %q config merge: %w", name, err)
		}

		outputs[name] = pipeline.NewOutput(driver, &merged, r.deps.Metrics)
	}

	return outputs, nil
}

func closeOutputs(outputs map[string]*pipeline.Output) {
	for _, out := range outputs {
		_ = out.Close()
	}
}
