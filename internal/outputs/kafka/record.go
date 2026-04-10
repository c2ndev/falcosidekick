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

package kafka

import (
	"encoding/json"
	"fmt"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

// buildRecord creates a Kafka record from a Falco event with key, headers, and topic resolution.
func (o *output) buildRecord(event *domain.Event) (*kgo.Record, error) {
	data, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("kafka marshal: %w", err)
	}

	return &kgo.Record{
		Topic:   o.resolveTopic(event),
		Value:   data,
		Key:     o.resolveKey(event),
		Headers: buildHeaders(event),
	}, nil
}

// resolveTopic returns the topic for this event.
// If topic_field is configured and the field exists in the event, use it.
// Otherwise use the default static topic.
func (o *output) resolveTopic(event *domain.Event) string {
	if o.cfg.TopicField != "" {
		if v, ok := event.OutputFields[o.cfg.TopicField]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return o.cfg.Topic
}

// resolveKey returns the message key for partition affinity.
// Priority: message_key_field (dynamic) > message_key (static) > nil (round-robin).
func (o *output) resolveKey(event *domain.Event) []byte {
	if o.cfg.MessageKeyField != "" {
		if v, ok := event.OutputFields[o.cfg.MessageKeyField]; ok {
			if s, ok := v.(string); ok && s != "" {
				return []byte(s)
			}
		}
	}
	if o.cfg.MessageKey != "" {
		return []byte(o.cfg.MessageKey)
	}
	return nil
}

// buildHeaders creates Kafka record headers for consumer-side routing/filtering.
func buildHeaders(event *domain.Event) []kgo.RecordHeader {
	return []kgo.RecordHeader{
		{Key: "content-type", Value: []byte("application/json")},
		{Key: "falco.rule", Value: []byte(event.Rule)},
		{Key: "falco.priority", Value: []byte(string(event.Priority))},
		{Key: "falco.source", Value: []byte(event.Source)},
	}
}
