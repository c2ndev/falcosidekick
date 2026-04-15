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

package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestRuntimeDefaultsValidateValid(t *testing.T) {
	cfg := defaultRuntimeDefaults()
	assert.Empty(t, cfg.Validate())
}

func TestRuntimeDefaultsValidateZeroValues(t *testing.T) {
	cfg := output.RuntimeConfig{}
	assert.NotEmpty(t, cfg.Validate())
}

func TestRuntimeDefaultsValidateNegativeQueueSize(t *testing.T) {
	cfg := defaultRuntimeDefaults()
	cfg.QueueSize = -1
	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
}

func TestOutputGetStatus(t *testing.T) {
	out := NewOutput(&testutil.MockDriver{DriverName: "slack"}, defaultRuntimeDefaults(), nil)

	status := out.GetStatus()
	assert.Equal(t, "slack", status.Name)
	assert.Equal(t, 0, status.QueueDepth)
	assert.Equal(t, 100, status.QueueCapacity)
	assert.Equal(t, "closed", status.CircuitState)
}

func TestOutputDropsWhenQueueFull(t *testing.T) {
	blocked := make(chan struct{})
	cfg := defaultRuntimeDefaults()
	cfg.QueueSize = 2
	cfg.Workers = 1

	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			<-blocked
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 5; i++ {
		out.Enqueue(newTestEvent())
	}

	assert.Greater(t, out.droppedTotal.Load(), int64(0))

	close(blocked)
	out.CloseQueue()
	out.WaitDone()
}
