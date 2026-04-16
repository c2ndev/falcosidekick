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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

func stubOutputType(name string, sendFunc func(context.Context, *event.Event) error) output.Type {
	return output.Type{
		Name: name,
		Schema: output.Schema{
			Fields: []output.SchemaField{},
		},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{
				DriverName: name,
				SendFunc:   sendFunc,
			}, nil
		},
	}
}

func failingInitOutputType(name string) output.Type {
	return output.Type{
		Name: name,
		Schema: output.Schema{
			Fields: []output.SchemaField{},
		},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &failingInitDriver{MockDriver: testutil.MockDriver{DriverName: name}}, nil
		},
	}
}

type failingInitDriver struct {
	testutil.MockDriver
}

func (d *failingInitDriver) Init(_ context.Context) error {
	return fmt.Errorf("init failed for %s", d.DriverName)
}

func testRuntimeDefaults() output.RuntimeConfig {
	return output.RuntimeConfig{
		QueueSize: 100,
		Workers:   1,
		Retry: &output.RetryConfig{
			MaxAttempts:     1,
			InitialInterval: 10 * time.Millisecond,
			MaxInterval:     100 * time.Millisecond,
			Multiplier:      2.0,
		},
		CircuitBreaker: &output.CircuitBreakerConfig{
			FailureThreshold: 5,
			SuccessThreshold: 2,
			ResetTimeout:     30 * time.Second,
		},
	}
}

func writeOutputsYAML(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// reloaderTestEnv sets up a dispatcher with workerRunCtx for reloader tests.
type reloaderTestEnv struct {
	d            *pipeline.Dispatcher
	workerRunCtx context.Context
	stopWorkers  context.CancelFunc
}

func newReloaderTestEnv(t *testing.T, outputs []*pipeline.Output) *reloaderTestEnv {
	t.Helper()
	d := pipeline.NewDispatcher(outputs)
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)
	return &reloaderTestEnv{d: d, workerRunCtx: workerRunCtx, stopWorkers: stopWorkers}
}

func (e *reloaderTestEnv) shutdown(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = e.d.Shutdown(ctx, e.stopWorkers)
}

func TestReloaderSuccessAddOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    webhook_url: https://hooks.slack.com/new\n")

	var slackCalls atomic.Int64
	cat, err := catalog.New([]output.Type{
		stubOutputType("slack", func(_ context.Context, _ *event.Event) error {
			slackCalls.Add(1)
			return nil
		}),
	})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testRuntimeDefaults(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))

	env.d.DispatchEvent(&event.Event{
		Priority: event.PriorityError,
		Rule:     "test",
		Source:   "test",
	})

	env.shutdown(t)

	assert.Equal(t, int64(1), slackCalls.Load())
}

func TestReloaderSuccessRemoveOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs: {}\n")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	initialOut := pipeline.NewOutput(&testutil.MockDriver{DriverName: "slack"}, &output.RuntimeConfig{
		QueueSize: 100, Workers: 1,
		Retry:          &output.RetryConfig{MaxAttempts: 1, InitialInterval: time.Millisecond, MaxInterval: time.Millisecond, Multiplier: 1},
		CircuitBreaker: &output.CircuitBreakerConfig{FailureThreshold: 5, SuccessThreshold: 2, ResetTimeout: time.Second},
	}, nil)

	env := newReloaderTestEnv(t, []*pipeline.Output{initialOut})
	defer env.shutdown(t)

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testRuntimeDefaults(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{"slack": {"webhook_url": "old"}},
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))

	names := env.d.OutputNames()
	assert.Empty(t, names, "slack must be removed")
}

func TestReloaderNoChangeIsNoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    webhook_url: same\n")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	initial := map[string]map[string]any{"slack": {"webhook_url": "same"}}
	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testRuntimeDefaults(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  initial,
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))
}

func TestReloaderParseErrorKeepsOldConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "invalid: [yaml: {{{")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testRuntimeDefaults(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{"slack": {"webhook_url": "old"}},
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reload parse")
}

func TestReloaderUnknownOutputKeepsOldConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  unknown_output:\n    url: http://x\n")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testRuntimeDefaults(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown output type")
}

func TestReloaderConcurrentReloadsSerialized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  loki:\n    url: http://loki:3100\n")

	cat, err := catalog.New([]output.Type{stubOutputType("loki", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testRuntimeDefaults(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	var wg sync.WaitGroup
	var errCount atomic.Int64
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second); err != nil {
				errCount.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(0), errCount.Load())
}

func TestReloaderChangedOutputTriggersReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")

	var calls atomic.Int64
	cat, err := catalog.New([]output.Type{
		stubOutputType("slack", func(_ context.Context, _ *event.Event) error {
			calls.Add(1)
			return nil
		}),
	})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	initial := map[string]map[string]any{"slack": {"webhook_url": "old"}}
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    webhook_url: old\n")

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testRuntimeDefaults(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  initial,
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))

	writeOutputsYAML(t, path, "outputs:\n  slack:\n    webhook_url: new\n")
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))

	env.d.DispatchEvent(&event.Event{
		Priority: event.PriorityError,
		Rule:     "test",
		Source:   "test",
	})

	env.shutdown(t)

	assert.GreaterOrEqual(t, calls.Load(), int64(1), "replaced output must receive events")
}

func TestReloaderInitFailureClosesPartialOutputs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    webhook_url: x\n  broken:\n    url: y\n")

	var closeCalled atomic.Bool
	slackType := output.Type{
		Name:   "slack",
		Schema: output.Schema{Fields: []output.SchemaField{}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{
				DriverName: "slack",
				CloseFunc: func() error {
					closeCalled.Store(true)
					return nil
				},
			}, nil
		},
	}

	cat, err := catalog.New([]output.Type{
		slackType,
		failingInitOutputType("broken"),
	})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testRuntimeDefaults(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second)
	assert.Error(t, err, "reload must fail when any output Init fails")
	assert.Contains(t, err.Error(), "init")

	assert.Empty(t, env.d.OutputNames(), "no outputs must be added on partial failure")
}

const (
	metricReloadTotal       = "falcosidekick_reload_total"
	metricReloadFailures    = "falcosidekick_reload_failures_total"
	metricReloadPartial     = "falcosidekick_reload_partial_total"
	metricReloadLastSuccess = "falcosidekick_reload_last_success_timestamp"
)

// mockDatabase implements core.Database for testing reload DB sync paths.
type mockDatabase struct {
	provisionErr error
}

func (m *mockDatabase) Provision(_ context.Context, _ *core.ProvisionRequest) error {
	return m.provisionErr
}
func (m *mockDatabase) GetConfig(_ context.Context) (*core.ConfigEntry, error) { return nil, nil }
func (m *mockDatabase) SaveConfig(_ context.Context, _ *core.Config) error     { return nil }
func (m *mockDatabase) GetOutputConfigs(_ context.Context) (map[string]core.OutputConfigEntry, error) {
	return nil, nil
}
func (m *mockDatabase) GetOutputConfig(_ context.Context, _ string) (*core.OutputConfigEntry, error) {
	return nil, nil
}
func (m *mockDatabase) SaveOutputConfig(_ context.Context, _ string, _ map[string]any) error {
	return nil
}
func (m *mockDatabase) DeleteOutputConfig(_ context.Context, _ string) error { return nil }
func (m *mockDatabase) GetPipelineLayout(_ context.Context) (*core.PipelineLayout, error) {
	return nil, nil
}
func (m *mockDatabase) SavePipelineLayout(_ context.Context, _ *core.PipelineLayout) error {
	return nil
}
func (m *mockDatabase) Close() error { return nil }

// getMetricValue extracts a counter or gauge value from a gathered metric family.
func getMetricValue(gathered []*dto.MetricFamily, name string) float64 {
	for _, mf := range gathered {
		if mf.GetName() == name {
			return mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	return 0
}

// getLastSuccessTimestamp extracts the reload_last_success_timestamp gauge value.
func getLastSuccessTimestamp(gathered []*dto.MetricFamily) float64 {
	for _, mf := range gathered {
		if mf.GetName() == metricReloadLastSuccess {
			return mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	return 0
}

func TestReloaderReplaceRetireTimeoutKeepsLiveReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")

	var newSendCalls atomic.Int64
	fastType := output.Type{
		Name:   "myout",
		Schema: output.Schema{Fields: []output.SchemaField{}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{
				DriverName: "myout",
				SendFunc: func(_ context.Context, _ *event.Event) error {
					newSendCalls.Add(1)
					return nil
				},
			}, nil
		},
	}
	cat, err := catalog.New([]output.Type{fastType})
	require.NoError(t, err)

	// Start with a slow output whose Send blocks forever (ignores ctx).
	slowDriver := &testutil.MockDriver{
		DriverName: "myout",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			select {} // block forever
		},
	}
	initialOut := pipeline.NewOutput(slowDriver, &output.RuntimeConfig{
		QueueSize: 100, Workers: 1,
		Retry:          &output.RetryConfig{MaxAttempts: 1, InitialInterval: time.Millisecond, MaxInterval: time.Millisecond, Multiplier: 1},
		CircuitBreaker: &output.CircuitBreakerConfig{FailureThreshold: 5, SuccessThreshold: 2, ResetTimeout: time.Second},
	}, nil)

	env := newReloaderTestEnv(t, []*pipeline.Output{initialOut})
	defer env.shutdown(t)

	// Feed an event so the slow worker enters blocking Send.
	env.d.DispatchEvent(&event.Event{Priority: event.PriorityError, Rule: "test", Source: "test"})
	time.Sleep(30 * time.Millisecond)

	// Changed config triggers a replace.
	writeOutputsYAML(t, path, "outputs:\n  myout:\n    url: http://changed\n")

	reg := prometheus.NewRegistry()
	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testRuntimeDefaults(),
		Deps:            output.Deps{Logger: slog.Default()},
		Registry:        reg,
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{"myout": {"url": "http://old"}},
	})

	// Broad reloadCtx (for Init/Provision), short retireTimeout so old output retire times out.
	reloadCtx, reloadCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reloadCancel()
	err = r.Reload(reloadCtx, env.workerRunCtx, 100*time.Millisecond)

	require.NoError(t, err, "Reload must succeed: replacement is live, retire timeout is a warning")

	env.d.DispatchEvent(&event.Event{Priority: event.PriorityError, Rule: "test2", Source: "test"})
	time.Sleep(50 * time.Millisecond)
	assert.GreaterOrEqual(t, newSendCalls.Load(), int64(1), "live replacement must receive events")

	assert.Equal(t, "http://changed", r.current["myout"]["url"], "current state must reflect new config")

	gathered, gatherErr := reg.Gather()
	require.NoError(t, gatherErr)
	assert.Equal(t, float64(1), getMetricValue(gathered, metricReloadTotal), "reload_total must be 1")
	assert.Equal(t, float64(0), getMetricValue(gathered, metricReloadFailures), "reload_failures_total must be 0")
	assert.Equal(t, float64(1), getMetricValue(gathered, metricReloadPartial), "reload_partial_total must be 1")
	assert.Equal(t, float64(0), getLastSuccessTimestamp(gathered), "reload_last_success_timestamp must NOT be updated on partial")
}

func TestReloaderRemoveRetireTimeoutIsWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")

	slowDriver := &testutil.MockDriver{
		DriverName: "myout",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			select {} // block forever
		},
	}
	initialOut := pipeline.NewOutput(slowDriver, &output.RuntimeConfig{
		QueueSize: 100, Workers: 1,
		Retry:          &output.RetryConfig{MaxAttempts: 1, InitialInterval: time.Millisecond, MaxInterval: time.Millisecond, Multiplier: 1},
		CircuitBreaker: &output.CircuitBreakerConfig{FailureThreshold: 5, SuccessThreshold: 2, ResetTimeout: time.Second},
	}, nil)

	cat, err := catalog.New([]output.Type{stubOutputType("myout", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, []*pipeline.Output{initialOut})
	defer env.shutdown(t)

	// Feed event to block the worker.
	env.d.DispatchEvent(&event.Event{Priority: event.PriorityError, Rule: "test", Source: "test"})
	time.Sleep(30 * time.Millisecond)

	writeOutputsYAML(t, path, "outputs: {}\n")

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testRuntimeDefaults(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{"myout": {"url": "http://old"}},
	})

	reloadCtx, reloadCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reloadCancel()
	err = r.Reload(reloadCtx, env.workerRunCtx, 100*time.Millisecond)

	require.NoError(t, err, "Reload must succeed: retire timeout is a warning")
	assert.Empty(t, env.d.OutputNames(), "output must be removed from dispatcher")
}

func TestReloaderRejectsDuringShutdown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    webhook_url: x\n")

	var closeCalled atomic.Bool
	slackType := output.Type{
		Name:   "slack",
		Schema: output.Schema{Fields: []output.SchemaField{}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{
				DriverName: "slack",
				CloseFunc: func() error {
					closeCalled.Store(true)
					return nil
				},
			}, nil
		},
	}

	cat, err := catalog.New([]output.Type{slackType})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)

	// Stop the dispatcher BEFORE reload.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	defer shutdownCancel()
	_ = env.d.Shutdown(shutdownCtx, env.stopWorkers)

	reg := prometheus.NewRegistry()
	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testRuntimeDefaults(),
		Deps:            output.Deps{Logger: slog.Default()},
		Registry:        reg,
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	reloadCtx, reloadCancel := context.WithTimeout(context.Background(), time.Second)
	defer reloadCancel()
	err = r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "dispatcher stopped")

	assert.True(t, closeCalled.Load(), "orphaned output must be closed on rejection")
	assert.Empty(t, r.current, "current state must not be updated on rejected reload")

	gathered, gatherErr := reg.Gather()
	require.NoError(t, gatherErr)
	assert.Equal(t, float64(1), getMetricValue(gathered, metricReloadFailures), "reload_failures_total must be 1")
	assert.Equal(t, float64(0), getMetricValue(gathered, metricReloadPartial), "reload_partial_total must be 0")
	assert.Equal(t, float64(0), getLastSuccessTimestamp(gathered), "reload_last_success_timestamp must not be updated on failure")
}

func TestReloadRetireTimeoutConfigValidation(t *testing.T) {
	cfg := core.ReloadConfig{PollInterval: 0, RetireTimeout: -1 * time.Second}
	errs := cfg.Validate()
	assert.NotEmpty(t, errs, "negative retire_timeout must fail validation")
}

func TestReloadNoOpCountsAsAttempt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    url: same\n")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	reg := prometheus.NewRegistry()
	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testRuntimeDefaults(),
		Deps:            output.Deps{Logger: slog.Default()},
		Registry:        reg,
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{"slack": {"url": "same"}},
	})

	reloadCtx := context.Background()
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))

	gathered, gatherErr := reg.Gather()
	require.NoError(t, gatherErr)
	assert.Equal(t, float64(1), getMetricValue(gathered, metricReloadTotal), "no-op reload must still count as an attempt")
	assert.Equal(t, float64(0), getMetricValue(gathered, metricReloadFailures), "no-op must not be a failure")
	assert.Equal(t, float64(0), getMetricValue(gathered, metricReloadPartial), "no-op must not be partial")
	assert.Equal(t, float64(0), getLastSuccessTimestamp(gathered), "no-op must not update last success timestamp")
}

func TestReloaderSuccessWithDBSync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    webhook_url: https://hooks.slack.com/new\n")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	reg := prometheus.NewRegistry()
	db := &mockDatabase{}
	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		Database:        db,
		RuntimeDefaults: testRuntimeDefaults(),
		Deps:            output.Deps{Logger: slog.Default()},
		Registry:        reg,
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))

	assert.Contains(t, r.current, "slack", "current state must include new output")

	gathered, gatherErr := reg.Gather()
	require.NoError(t, gatherErr)
	assert.Equal(t, float64(1), getMetricValue(gathered, metricReloadTotal), "reload_total must be 1")
	assert.Equal(t, float64(0), getMetricValue(gathered, metricReloadFailures), "reload_failures_total must be 0")
	assert.Equal(t, float64(0), getMetricValue(gathered, metricReloadPartial), "reload_partial_total must be 0")
	assert.NotEqual(t, float64(0), getLastSuccessTimestamp(gathered), "reload_last_success_timestamp must be updated")
}

func TestReloaderPartialSuccessDBSyncFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    webhook_url: https://hooks.slack.com/new\n")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	reg := prometheus.NewRegistry()
	db := &mockDatabase{provisionErr: fmt.Errorf("db provision failed")}
	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		Database:        db,
		RuntimeDefaults: testRuntimeDefaults(),
		Deps:            output.Deps{Logger: slog.Default()},
		Registry:        reg,
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Reload returns nil because runtime accepted the new config even though DB failed.
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))

	assert.Contains(t, r.current, "slack", "current state must reflect new config despite DB failure")

	gathered, gatherErr := reg.Gather()
	require.NoError(t, gatherErr)
	assert.Equal(t, float64(1), getMetricValue(gathered, metricReloadTotal), "reload_total must be 1")
	assert.Equal(t, float64(0), getMetricValue(gathered, metricReloadFailures), "reload_failures_total must be 0")
	assert.Equal(t, float64(1), getMetricValue(gathered, metricReloadPartial), "reload_partial_total must be 1")
	assert.Equal(t, float64(0), getLastSuccessTimestamp(gathered), "reload_last_success_timestamp must NOT be updated on partial")
}
