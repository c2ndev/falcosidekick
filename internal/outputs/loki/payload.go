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
	"encoding/json"
	"log/slog"
	"sort"
	"strconv"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

const formatJSON = "json"

type lokiPayload struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"`
}

// buildPayload creates a Loki push payload for a single event.
func buildPayload(logFormat string, extraLabels []string, event *domain.Event) lokiPayload {
	labels := extractLabels(extraLabels, event)
	entry := formatEntry(logFormat, event)

	return lokiPayload{
		Streams: []lokiStream{
			{Stream: labels, Values: [][]string{entry}},
		},
	}
}

// buildBatchPayload creates a Loki push payload for multiple events.
// Events with identical label sets are grouped into the same stream.
// Entries within each stream are sorted by timestamp (Loki requirement).
func buildBatchPayload(logFormat string, extraLabels []string, events []*domain.Event) lokiPayload {
	streamMap := make(map[string]*lokiStream)
	streamOrder := make([]string, 0)

	for _, event := range events {
		labels := extractLabels(extraLabels, event)
		key := serializeLabels(labels)
		entry := formatEntry(logFormat, event)

		if s, ok := streamMap[key]; ok {
			s.Values = append(s.Values, entry)
		} else {
			streamMap[key] = &lokiStream{Stream: labels, Values: [][]string{entry}}
			streamOrder = append(streamOrder, key)
		}
	}

	streams := make([]lokiStream, 0, len(streamMap))
	for _, key := range streamOrder {
		s := streamMap[key]
		sortEntriesByTimestamp(s.Values)
		streams = append(streams, *s)
	}

	return lokiPayload{Streams: streams}
}

// formatEntry creates a Loki entry [timestamp, line] pair.
func formatEntry(logFormat string, event *domain.Event) []string {
	ts := strconv.FormatInt(event.Time.UnixNano(), 10)

	var line string
	if logFormat == formatJSON {
		data, err := json.Marshal(event)
		if err == nil {
			line = string(data)
		} else {
			slog.Warn("loki: json marshal failed, using raw output", "error", err)
			line = event.Output
		}
	} else {
		line = event.Output
	}

	return []string{ts, line}
}

func sortEntriesByTimestamp(entries [][]string) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i][0] < entries[j][0]
	})
}
