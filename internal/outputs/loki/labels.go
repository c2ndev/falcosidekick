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

package loki

import (
	"fmt"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain"
	"github.com/falcosecurity/falcosidekick/internal/outputs/sdk"
)

// extractLabels builds the label set for a Falco event.
func extractLabels(extraLabels []string, event *domain.Event) map[string]string {
	labels := map[string]string{
		"rule":     event.Rule,
		"source":   event.Source,
		"priority": string(event.Priority),
	}

	if event.Hostname != "" {
		labels["hostname"] = event.Hostname
	}

	if tags := sdk.FormatTags(event.Tags, ","); tags != "" {
		labels["tags"] = tags
	}

	if ns, ok := event.OutputFields["k8s.ns.name"]; ok {
		labels["k8s_ns_name"] = fmt.Sprintf("%v", ns)
	}
	if pod, ok := event.OutputFields["k8s.pod.name"]; ok {
		labels["k8s_pod_name"] = fmt.Sprintf("%v", pod)
	}

	for _, field := range extraLabels {
		if v, ok := event.OutputFields[field]; ok {
			labels[sdk.SanitizeLabel(field)] = fmt.Sprintf("%v", v)
		}
	}

	return labels
}

// serializeLabels creates a deterministic string key for stream grouping.
func serializeLabels(labels map[string]string) string {
	keys := sdk.SortMapKeys(labels)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(labels[k])
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}
