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

package alertmanager

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/outputs/sdk"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestBuildAlertIncludesAlertname(t *testing.T) {
	o := &output{cfg: config{}}
	event := testutil.CreateValidEvent()
	alert := o.buildAlert(event)

	assert.NotEmpty(t, alert.Labels["alertname"], "must set alertname for AM routing")
	assert.Equal(t, sdk.SanitizeLabel(event.Rule), alert.Labels["alertname"])
}

func TestBuildAlertIncludesStartsAt(t *testing.T) {
	o := &output{cfg: config{}}
	event := testutil.CreateValidEvent()
	alert := o.buildAlert(event)

	assert.NotEmpty(t, alert.StartsAt, "must set startsAt for dedup/timing")
	assert.Contains(t, alert.StartsAt, "T", "startsAt must be RFC3339")
}

func TestBuildAlertIncludesGeneratorURL(t *testing.T) {
	o := &output{cfg: config{GeneratorURL: "http://sidekick:2801"}}
	event := testutil.CreateValidEvent()
	alert := o.buildAlert(event)

	assert.Equal(t, "http://sidekick:2801", alert.GeneratorURL)
}

func TestBuildAlertNoGeneratorURLWhenEmpty(t *testing.T) {
	o := &output{cfg: config{}}
	event := testutil.CreateValidEvent()
	alert := o.buildAlert(event)

	assert.Empty(t, alert.GeneratorURL)
}

func TestBuildAlertNoHostnameWhenEmpty(t *testing.T) {
	o := &output{cfg: config{}}
	event := testutil.CreateValidEvent()
	event.Hostname = ""
	alert := o.buildAlert(event)

	_, has := alert.Labels["hostname"]
	assert.False(t, has, "empty hostname must not produce a label")
}

func TestBuildAlertExtraAnnotations(t *testing.T) {
	o := &output{cfg: config{
		ExtraAnnotations: map[string]string{
			"runbook": "https://example.com/runbook",
			"team":    "security",
		},
	}}
	event := testutil.CreateValidEvent()
	alert := o.buildAlert(event)

	assert.Equal(t, "https://example.com/runbook", alert.Annotations["runbook"])
	assert.Equal(t, "security", alert.Annotations["team"])
	assert.NotEmpty(t, alert.Annotations["info"])
}

func TestBuildAlertNoExpiresAfter(t *testing.T) {
	o := &output{cfg: config{}}
	alert := o.buildAlert(testutil.CreateValidEvent())
	assert.Empty(t, alert.EndsAt)
}

func TestBuildAlertExpiresAfter(t *testing.T) {
	o := &output{cfg: config{ExpiresAfter: 300}}
	alert := o.buildAlert(testutil.CreateValidEvent())
	assert.NotEmpty(t, alert.EndsAt)
}

func TestBuildAlertTagsSorted(t *testing.T) {
	o := &output{cfg: config{}}
	event := testutil.CreateValidEvent()
	event.Tags = []string{"z_tag", "a_tag", "m_tag"}
	alert := o.buildAlert(event)

	assert.Equal(t, "a_tag,m_tag,z_tag", alert.Labels["tags"])
}

func TestBuildAlertNoTags(t *testing.T) {
	o := &output{cfg: config{}}
	event := testutil.CreateValidEvent()
	event.Tags = nil
	alert := o.buildAlert(event)

	_, has := alert.Labels["tags"]
	assert.False(t, has)
}

func TestBuildAlertExtraLabels(t *testing.T) {
	o := &output{cfg: config{
		ExtraLabels: map[string]string{"env": "production", "k8s.ns": "default"},
	}}
	alert := o.buildAlert(testutil.CreateValidEvent())

	assert.Equal(t, "production", alert.Labels["env"])
	assert.Equal(t, "default", alert.Labels["k8s_ns"])
}

func TestResolveSeverityUsesSharedDefault(t *testing.T) {
	o := &output{cfg: config{}}
	priorities := []domain.Priority{
		domain.PriorityDebug, domain.PriorityInformational, domain.PriorityNotice,
		domain.PriorityWarning, domain.PriorityError, domain.PriorityCritical,
		domain.PriorityAlert, domain.PriorityEmergency,
	}
	for _, p := range priorities {
		t.Run(string(p), func(t *testing.T) {
			assert.Equal(t, sdk.PrioritySeverity(p), o.resolveSeverity(p))
		})
	}
}

func TestResolveSeverityCustomMapOverride(t *testing.T) {
	o := &output{cfg: config{
		CustomSeverityMap: map[string]string{"critical": "P1", "warning": "P3"},
	}}
	assert.Equal(t, "P1", o.resolveSeverity(domain.PriorityCritical))
	assert.Equal(t, "P3", o.resolveSeverity(domain.PriorityWarning))
	assert.Equal(t, sdk.PrioritySeverity(domain.PriorityDebug), o.resolveSeverity(domain.PriorityDebug))
}

func TestAlertmanagerMultiHost(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"hosts": []string{"http://am1:9093", "http://am2:9093"},
	}, domain.OutputDeps{})
	require.NoError(t, err)

	o := driver.(*output)
	assert.Len(t, o.hostURLs, 2)
	assert.NotNil(t, o.sender)
}
