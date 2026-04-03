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

package utils

import (
	"fmt"
	"strings"
)

// ValidationError represents a single field validation failure.
type ValidationError struct {
	Field   string
	Message string
}

func (ve ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", ve.Field, ve.Message)
}

// ValidationErrors collects multiple validation failures.
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	var sb strings.Builder
	for i, err := range ve {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(err.Error())
	}
	return sb.String()
}

// Add appends a validation error for the given field.
func (ve *ValidationErrors) Add(field, msg string) {
	*ve = append(*ve, ValidationError{Field: field, Message: msg})
}

// Merge appends nested errors with an optional field prefix.
func (ve *ValidationErrors) Merge(prefix string, nested ValidationErrors) {
	for _, err := range nested {
		field := err.Field
		if prefix != "" {
			field = prefix + "." + field
		}
		ve.Add(field, err.Message)
	}
}
