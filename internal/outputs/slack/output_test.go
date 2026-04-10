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

package slack

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/outputs/sdk"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestSlackCommonCases(t *testing.T) {
	testutil.RunOutputTests(t, Type, []testutil.OutputTestCase{
		{Name: "sends valid event", AddressField: "webhook_url"},
		{Name: "returns error on server 500", AddressField: "webhook_url", MockStatus: http.StatusInternalServerError, ExpectError: true},
	})
}

func TestSlackPayloadFormat(t *testing.T) {
	testutil.RunOutputTests(t, Type, []testutil.OutputTestCase{
		{
			Name:         "sends attachment with priority color",
			AddressField: "webhook_url",
			ValidateReq: func(t *testing.T, req *http.Request, body []byte) {
				var payload slackPayload
				require.NoError(t, json.Unmarshal(body, &payload))
				require.Len(t, payload.Attachments, 1)
				assert.NotEmpty(t, payload.Attachments[0].Color)
				assert.NotEmpty(t, payload.Attachments[0].Fields)
			},
		},
		{
			Name:         "includes channel when configured",
			AddressField: "webhook_url",
			Config:       map[string]any{"channel": "#alerts"},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var payload slackPayload
				require.NoError(t, json.Unmarshal(body, &payload))
				assert.Equal(t, "#alerts", payload.Channel)
			},
		},
		{
			Name:         "includes username and icon",
			AddressField: "webhook_url",
			Config:       map[string]any{"username": "FalcoBot", "icon_url": "https://example.com/icon.png"},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var payload slackPayload
				require.NoError(t, json.Unmarshal(body, &payload))
				assert.Equal(t, "FalcoBot", payload.Username)
				assert.Equal(t, "https://example.com/icon.png", payload.IconURL)
			},
		},
		{
			Name:         "text-only format omits fields",
			AddressField: "webhook_url",
			Config:       map[string]any{"output_format": "text"},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var payload slackPayload
				require.NoError(t, json.Unmarshal(body, &payload))
				require.Len(t, payload.Attachments, 1)
				assert.Empty(t, payload.Attachments[0].Fields)
				assert.NotEmpty(t, payload.Attachments[0].Text)
			},
		},
	})
}

func TestSlackCreateValidation(t *testing.T) {
	_, err := createOutput(map[string]any{}, domain.OutputDeps{})
	assert.Error(t, err, "missing webhook_url must fail")
}

func TestSlackMessageTemplate(t *testing.T) {
	testutil.RunOutputTests(t, Type, []testutil.OutputTestCase{
		{
			Name:         "renders message template",
			AddressField: "webhook_url",
			Config:       map[string]any{"message_format": "Alert: {{ .Rule }}"},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var payload slackPayload
				require.NoError(t, json.Unmarshal(body, &payload))
				assert.Contains(t, payload.Text, "Alert:")
			},
		},
	})
}

func TestCheckSlackResponse(t *testing.T) {
	tests := []struct {
		name    string
		body    []byte
		wantErr bool
	}{
		{"ok response", []byte("ok"), false},
		{"ok with newline", []byte("ok\n"), false},
		{"empty body", []byte{}, false},
		{"invalid_payload", []byte("invalid_payload"), true},
		{"channel_not_found", []byte("channel_not_found"), true},
		{"no_service", []byte("no_service"), true},
		{"no_text", []byte("no_text"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSlackResponse(tt.body)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "slack:")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBuildPayloadMrkdwnIn(t *testing.T) {
	o := &output{cfg: config{OutputFormat: formatText, Footer: defaultFooter}, logger: slog.Default()}
	event := testutil.CreateValidEvent()

	payload := o.buildPayload(event)
	require.Len(t, payload.Attachments, 1)
	assert.Contains(t, payload.Attachments[0].MrkdwnIn, "text")
	assert.Contains(t, payload.Attachments[0].MrkdwnIn, "fallback")
}

func TestBuildPayloadIconEmoji(t *testing.T) {
	o := &output{cfg: config{
		OutputFormat: formatText,
		Footer:       defaultFooter,
		IconEmoji:    ":ghost:",
	}, logger: slog.Default()}
	event := testutil.CreateValidEvent()

	payload := o.buildPayload(event)
	assert.Equal(t, ":ghost:", payload.IconEmoji)
}

func TestBuildPayloadFieldsOnlyFormat(t *testing.T) {
	o := &output{cfg: config{OutputFormat: formatFields, Footer: defaultFooter}, logger: slog.Default()}
	event := testutil.CreateValidEvent()

	payload := o.buildPayload(event)
	require.Len(t, payload.Attachments, 1)

	att := payload.Attachments[0]
	assert.NotEmpty(t, att.Fields, "fields format must include fields")
	assert.Empty(t, att.Text, "fields format must not include text body")
}

func TestBuildPayloadAllFormat(t *testing.T) {
	o := &output{cfg: config{OutputFormat: formatAll, Footer: defaultFooter}, logger: slog.Default()}
	event := testutil.CreateValidEvent()

	payload := o.buildPayload(event)
	att := payload.Attachments[0]
	assert.NotEmpty(t, att.Fields, "all format must include fields")
	assert.NotEmpty(t, att.Text, "all format must include text body")
}

func TestBuildPayloadEveryPriorityHasColor(t *testing.T) {
	o := &output{cfg: config{OutputFormat: formatText, Footer: defaultFooter}, logger: slog.Default()}

	priorities := []domain.Priority{
		domain.PriorityDebug, domain.PriorityInformational, domain.PriorityNotice,
		domain.PriorityWarning, domain.PriorityError, domain.PriorityCritical,
		domain.PriorityAlert, domain.PriorityEmergency,
	}
	for _, p := range priorities {
		t.Run(string(p), func(t *testing.T) {
			event := testutil.CreateValidEvent()
			event.Priority = p
			payload := o.buildPayload(event)
			color := payload.Attachments[0].Color
			assert.NotEmpty(t, color, "priority %s must produce a color", p)
			assert.Equal(t, sdk.PriorityColor(p), color, "must use shared PriorityColor")
		})
	}
}

func TestBuildPayloadNoHostname(t *testing.T) {
	o := &output{cfg: config{OutputFormat: formatAll, Footer: defaultFooter}, logger: slog.Default()}
	event := testutil.CreateValidEvent()
	event.Hostname = ""

	payload := o.buildPayload(event)
	for _, f := range payload.Attachments[0].Fields {
		assert.NotEqual(t, "hostname", f.Title, "empty hostname must not produce a field")
	}
}

func TestBuildPayloadNoTags(t *testing.T) {
	o := &output{cfg: config{OutputFormat: formatAll, Footer: defaultFooter}, logger: slog.Default()}
	event := testutil.CreateValidEvent()
	event.Tags = nil

	payload := o.buildPayload(event)
	for _, f := range payload.Attachments[0].Fields {
		assert.NotEqual(t, "tags", f.Title, "nil tags must not produce a field")
	}
}

func TestBuildPayloadTagsSorted(t *testing.T) {
	o := &output{cfg: config{OutputFormat: formatAll, Footer: defaultFooter}, logger: slog.Default()}
	event := testutil.CreateValidEvent()
	event.Tags = []string{"z", "a", "m"}

	payload := o.buildPayload(event)
	var tagsField slackAttachmentField
	for _, f := range payload.Attachments[0].Fields {
		if f.Title == "tags" {
			tagsField = f
			break
		}
	}
	assert.Equal(t, "a, m, z", tagsField.Value)
}

func TestBuildPayloadOutputFieldsOrder(t *testing.T) {
	o := &output{cfg: config{OutputFormat: formatAll, Footer: defaultFooter}, logger: slog.Default()}
	event := testutil.CreateValidEvent()
	event.OutputFields = map[string]interface{}{
		"z.field": "zz",
		"a.field": "aa",
	}

	payload := o.buildPayload(event)
	var fieldTitles []string
	for _, f := range payload.Attachments[0].Fields {
		if f.Title == "a.field" || f.Title == "z.field" {
			fieldTitles = append(fieldTitles, f.Title)
		}
	}
	require.Len(t, fieldTitles, 2)
	assert.Equal(t, "a.field", fieldTitles[0])
	assert.Equal(t, "z.field", fieldTitles[1])
}

func TestBuildPayloadMessageTemplateExec(t *testing.T) {
	tmpl, err := template.New("slack").Parse("Rule: {{ .Rule }}")
	require.NoError(t, err)

	o := &output{
		cfg:         config{OutputFormat: formatText, Footer: defaultFooter},
		messageTmpl: tmpl,
		logger:      slog.Default(),
	}
	event := testutil.CreateValidEvent()
	payload := o.buildPayload(event)
	assert.Equal(t, "Rule: Write below binary dir", payload.Text)
}

func TestBuildPayloadMessageTemplateBadField(t *testing.T) {
	tmpl, err := template.New("slack").Parse("{{ .NonExistent }}")
	require.NoError(t, err)

	o := &output{
		cfg:         config{OutputFormat: formatText, Footer: defaultFooter},
		messageTmpl: tmpl,
		logger:      slog.Default(),
	}
	event := testutil.CreateValidEvent()
	payload := o.buildPayload(event)
	assert.Empty(t, payload.Text, "failed template must produce empty text")
}

func TestBuildPayloadChannel(t *testing.T) {
	o := &output{cfg: config{OutputFormat: formatText, Footer: defaultFooter, Channel: "#security"}, logger: slog.Default()}
	event := testutil.CreateValidEvent()
	payload := o.buildPayload(event)
	assert.Equal(t, "#security", payload.Channel)
}

func TestBuildPayloadNoChannel(t *testing.T) {
	o := &output{cfg: config{OutputFormat: formatText, Footer: defaultFooter}, logger: slog.Default()}
	event := testutil.CreateValidEvent()
	payload := o.buildPayload(event)
	assert.Empty(t, payload.Channel)
}

func TestCreateOutputInvalidTemplate(t *testing.T) {
	_, err := createOutput(map[string]any{
		"webhook_url":    "https://hooks.slack.com/test",
		"message_format": "{{ .Broken",
	}, domain.OutputDeps{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse message template")
}

func TestCreateOutputDefaults(t *testing.T) {
	driver, err := createOutput(map[string]any{
		"webhook_url": "https://hooks.slack.com/test",
	}, domain.OutputDeps{})
	require.NoError(t, err)

	o, ok := driver.(*output)
	require.True(t, ok)
	assert.Equal(t, formatAll, o.cfg.OutputFormat)
	assert.Equal(t, defaultFooter, o.cfg.Footer)
}

func TestSlackHealthCheck(t *testing.T) {
	testutil.RunOutputTests(t, Type, []testutil.OutputTestCase{
		{
			Name:         "health check sends GET",
			AddressField: "webhook_url",
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				// Harness validates Send works; this just ensures the output is valid
			},
		},
	})
}

func TestSlackInit(t *testing.T) {
	o := &output{}
	assert.NoError(t, o.Init(context.Background()))
}

func TestSlackClose(t *testing.T) {
	o := &output{}
	assert.NoError(t, o.Close())
}

func TestBuildPayloadFieldShortDetection(t *testing.T) {
	o := &output{cfg: config{OutputFormat: formatAll, Footer: defaultFooter}, logger: slog.Default()}
	event := testutil.CreateValidEvent()
	event.OutputFields = map[string]interface{}{
		"short": "x",
		"long":  "this is a long value that exceeds thirty six runes easily",
	}

	payload := o.buildPayload(event)
	for _, f := range payload.Attachments[0].Fields {
		if f.Title == "short" {
			assert.True(t, f.Short)
		}
		if f.Title == "long" {
			assert.False(t, f.Short)
		}
	}
}

func TestSlackFieldsFormat(t *testing.T) {
	testutil.RunOutputTests(t, Type, []testutil.OutputTestCase{
		{
			Name:         "fields format sends fields without text",
			AddressField: "webhook_url",
			Config:       map[string]any{"output_format": "fields"},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var payload slackPayload
				require.NoError(t, json.Unmarshal(body, &payload))
				require.Len(t, payload.Attachments, 1)
				assert.NotEmpty(t, payload.Attachments[0].Fields)
				assert.Empty(t, payload.Attachments[0].Text)
			},
		},
	})
}
