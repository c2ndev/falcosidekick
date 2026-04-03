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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

func newTestEvent() *domain.Event {
	return &domain.Event{
		Time:         time.Now(),
		Rule:         "Test rule",
		Priority:     domain.PriorityWarning,
		Output:       "test output",
		Source:       "syscall",
		OutputFields: map[string]interface{}{"proc.name": "bash"},
		Tags:         []string{"tag1"},
		Hostname:     "node-1",
	}
}

func testEnricherConfig() EnricherConfig {
	return EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	}
}

func TestNewEnricherWithValidConfig(t *testing.T) {
	e, err := NewEnricher(testEnricherConfig())
	require.NoError(t, err)
	require.NotNil(t, e)
}

func TestNewEnricherInvalidTemplate(t *testing.T) {
	_, err := NewEnricher(EnricherConfig{
		TemplatedFields: map[string]string{"bad": "{{ .Invalid | "},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse template")
}

func TestEnricherConfigValidateValid(t *testing.T) {
	cfg := testEnricherConfig()
	assert.Empty(t, cfg.Validate())
}

func TestEnricherConfigValidateNegativeEventThreshold(t *testing.T) {
	cfg := EnricherConfig{TruncateEventThreshold: -1}
	assert.NotEmpty(t, cfg.Validate())
}

func TestEnricherConfigValidateTooSmallFieldThreshold(t *testing.T) {
	cfg := EnricherConfig{TruncateEventThreshold: 100, TruncateFieldThreshold: 3}
	assert.NotEmpty(t, cfg.Validate())
}

func TestEnricherConfigValidateDisabledTruncation(t *testing.T) {
	cfg := EnricherConfig{TruncateEventThreshold: 0, TruncateFieldThreshold: 0}
	assert.Empty(t, cfg.Validate())
}

func TestEnricherConfigValidateZeroThresholds(t *testing.T) {
	cfg := EnricherConfig{}
	assert.Empty(t, cfg.Validate())
}

func TestEnrichGeneratesUUID(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	event := newTestEvent()

	require.NoError(t, e.Enrich(event))
	assert.NotEmpty(t, event.UUID)
	assert.Len(t, event.UUID, 36)
}

func TestEnrichUUIDUniqueness(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	e1 := newTestEvent()
	e2 := newTestEvent()

	require.NoError(t, e.Enrich(e1))
	require.NoError(t, e.Enrich(e2))
	assert.NotEqual(t, e1.UUID, e2.UUID)
}

func TestEnrichInjectsCustomFields(t *testing.T) {
	cfg := testEnricherConfig()
	cfg.CustomFields = map[string]string{"env": "prod", "cluster": "us-1"}
	e, _ := NewEnricher(cfg)
	event := newTestEvent()

	require.NoError(t, e.Enrich(event))
	assert.Equal(t, "prod", event.OutputFields["env"])
	assert.Equal(t, "us-1", event.OutputFields["cluster"])
	assert.Equal(t, "bash", event.OutputFields["proc.name"])
}

func TestEnrichEvaluatesTemplatedFields(t *testing.T) {
	cfg := testEnricherConfig()
	cfg.TemplatedFields = map[string]string{
		"proc_info": `process={{ index . "proc.name" }}`,
	}
	e, _ := NewEnricher(cfg)
	event := newTestEvent()

	require.NoError(t, e.Enrich(event))
	assert.Equal(t, "process=bash", event.OutputFields["proc_info"])
}

func TestEnrichTemplateErrorContinues(t *testing.T) {
	cfg := testEnricherConfig()
	cfg.TemplatedFields = map[string]string{
		"bad": `{{ call . }}`,
	}
	e, _ := NewEnricher(cfg)
	event := newTestEvent()

	require.NoError(t, e.Enrich(event))
	_, exists := event.OutputFields["bad"]
	assert.False(t, exists)
}

func TestEnrichInjectsCustomTags(t *testing.T) {
	cfg := testEnricherConfig()
	cfg.CustomTags = []string{"security", "falco"}
	e, _ := NewEnricher(cfg)
	event := newTestEvent()

	require.NoError(t, e.Enrich(event))
	assert.Equal(t, []string{"falco", "security", "tag1"}, event.Tags)
}

func TestEnrichNoCustomTagsPreservesOriginal(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	event := newTestEvent()
	original := make([]string, len(event.Tags))
	copy(original, event.Tags)

	require.NoError(t, e.Enrich(event))
	assert.Equal(t, original, event.Tags)
}

func TestEnrichDefaultHostname(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	event := newTestEvent()
	event.Hostname = ""

	require.NoError(t, e.Enrich(event))
	assert.Equal(t, defaultHostname, event.Hostname)
}

func TestEnrichPreservesExistingHostname(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	event := newTestEvent()

	require.NoError(t, e.Enrich(event))
	assert.Equal(t, "node-1", event.Hostname)
}

func TestEnrichReplacesBrackets(t *testing.T) {
	cfg := testEnricherConfig()
	cfg.BracketReplacer = "_"
	e, _ := NewEnricher(cfg)
	event := newTestEvent()
	const testPath = "/dev/null"
	event.OutputFields["fd[0]"] = testPath

	require.NoError(t, e.Enrich(event))
	assert.Equal(t, testPath, event.OutputFields["fd_0_"])
	_, hasBrackets := event.OutputFields["fd[0]"]
	assert.False(t, hasBrackets)
}

func TestEnrichNoBracketReplacerSkips(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	event := newTestEvent()
	const testPath = "/dev/null"
	event.OutputFields["fd[0]"] = testPath

	require.NoError(t, e.Enrich(event))
	assert.Equal(t, testPath, event.OutputFields["fd[0]"])
}

func TestEnrichTruncatesLargeEvents(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	event := newTestEvent()
	for i := 0; i < 10; i++ {
		event.OutputFields[strings.Repeat("field", i+1)] = strings.Repeat("x", 1000)
	}

	require.NoError(t, e.Enrich(event))

	truncated := false
	for _, v := range event.OutputFields {
		s, ok := v.(string)
		if ok && strings.HasSuffix(s, truncateFieldSuffix) {
			truncated = true
			assert.LessOrEqual(t, len(s), testEnricherConfig().TruncateFieldThreshold)
		}
	}
	assert.True(t, truncated, "at least one field should be truncated")
}

func TestEnrichCustomTruncateThresholds(t *testing.T) {
	e, _ := NewEnricher(EnricherConfig{
		TruncateEventThreshold: 200,
		TruncateFieldThreshold: 50,
	})
	event := newTestEvent()
	event.OutputFields["data"] = strings.Repeat("a", 100)

	require.NoError(t, e.Enrich(event))

	val := event.OutputFields["data"].(string)
	assert.LessOrEqual(t, len(val), 50)
	assert.True(t, strings.HasSuffix(val, truncateFieldSuffix))
}

func TestEnrichTruncateThresholdsFromConfig(t *testing.T) {
	cfg := testEnricherConfig()
	e, _ := NewEnricher(cfg)
	assert.Equal(t, cfg.TruncateEventThreshold, e.cfg.TruncateEventThreshold)
	assert.Equal(t, cfg.TruncateFieldThreshold, e.cfg.TruncateFieldThreshold)
}

func TestEnrichDoesNotTruncateSmallEvents(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	event := newTestEvent()
	event.OutputFields["small"] = "tiny"

	require.NoError(t, e.Enrich(event))
	assert.Equal(t, "tiny", event.OutputFields["small"])
}
