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

package shared

import (
	"fmt"
	"maps"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// Header holds public, secret, and file-backed values for one HTTP header.
// Files are validated at construction and reread on every request with surrounding
// whitespace removed. Relative paths resolve from the process working directory.
type Header struct {
	Values  []string `mapstructure:"values"`
	Secrets []string `mapstructure:"secrets"`
	Files   []string `mapstructure:"files"`
}

func decodeHeaderHook(_, to reflect.Type, data any) (any, error) {
	if to != reflect.TypeFor[Header]() {
		return data, nil
	}
	if h, ok := data.(Header); ok {
		return h, nil
	}
	raw := reflect.ValueOf(data)
	if raw.Kind() != reflect.Map {
		return nil, fmt.Errorf("header entry must be a map")
	}
	var h Header
	fields := []struct {
		values *[]string
		name   string
		seen   bool
	}{{&h.Values, "values", false}, {&h.Secrets, "secrets", false}, {&h.Files, "files", false}}
	iter := raw.MapRange()
	for iter.Next() {
		key, ok := iter.Key().Interface().(string)
		if !ok {
			return nil, fmt.Errorf("header property names must be strings")
		}
		matched := false
		for i := range fields {
			field := &fields[i]
			if !strings.EqualFold(key, field.name) {
				continue
			}
			if field.seen {
				return nil, fmt.Errorf("duplicate header property %s", field.name)
			}
			values, err := decodeHeaderList(iter.Value().Interface())
			if err != nil {
				return nil, fmt.Errorf("header %s: %w", field.name, err)
			}
			*field.values = values
			field.seen = true
			matched = true
			break
		}
		if !matched {
			return nil, fmt.Errorf("unknown header property")
		}
	}
	return h, nil
}

func decodeHeaderList(data any) ([]string, error) {
	switch values := data.(type) {
	case nil:
		return nil, nil
	case []string:
		return values, nil
	case []any:
		result := make([]string, len(values))
		for i, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("must be a list of strings")
			}
			result[i] = text
		}
		return result, nil
	default:
		return nil, fmt.Errorf("must be a list of strings")
	}
}

func validateHeaderNames(headers map[string]Header) error {
	seen := make(map[string]bool, len(headers))
	for _, name := range slices.Sorted(maps.Keys(headers)) {
		if !httpguts.ValidHeaderFieldName(name) {
			return fmt.Errorf("invalid header name")
		}
		canonical := http.CanonicalHeaderKey(name)
		if seen[canonical] {
			return fmt.Errorf("duplicate header name %q", canonical)
		}
		seen[canonical] = true
		switch canonical {
		case "Host", "Content-Length", "Transfer-Encoding", "Trailer", "Connection",
			"Keep-Alive", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization",
			"Te", "Upgrade", "Content-Encoding", "Accept-Encoding":
			return fmt.Errorf("header %q is owned by the HTTP transport", canonical)
		}
	}
	return nil
}

func (c *HTTPConfig) validateHeaders() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if err := validateHeaderNames(c.Headers); err != nil {
		errs.Add("headers", err.Error())
		return errs
	}
	for _, name := range slices.Sorted(maps.Keys(c.Headers)) {
		h := c.Headers[name]
		field := fmt.Sprintf("headers[%q]", name)
		if strings.EqualFold(name, "Authorization") {
			if len(h.Values) > 0 {
				errs.Add(field, "authorization must use secrets or files, not public values")
			}
			if c.Username != "" || c.Password != "" || c.BearerToken != "" {
				errs.Add(field, "cannot combine authorization with basic auth or bearer_token")
			}
		}
		if _, err := h.resolve(); err != nil {
			errs.Add(field, err.Error())
		}
	}
	return errs
}

func (h Header) resolve() ([]string, error) {
	values := make([]string, 0, len(h.Values)+len(h.Secrets)+len(h.Files))
	for _, group := range []struct {
		name   string
		values []string
	}{{"values", h.Values}, {"secrets", h.Secrets}} {
		for i, value := range group.values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return nil, fmt.Errorf("%s[%d]: invalid header value", group.name, i)
			}
			values = append(values, value)
		}
	}
	for i, path := range h.Files {
		b, err := os.ReadFile(path) //nolint:gosec // header secret paths are operator-configured
		if err != nil {
			return nil, fmt.Errorf("files[%d]: cannot read header file", i)
		}
		value := strings.TrimSpace(string(b))
		if !httpguts.ValidHeaderFieldValue(value) {
			return nil, fmt.Errorf("files[%d]: invalid header value", i)
		}
		values = append(values, value)
	}
	return values, nil
}

// ApplyHeaders replaces configured request headers in values, secrets, files order.
// It leaves the request unchanged if any header cannot be resolved or validated.
func ApplyHeaders(req *http.Request, headers map[string]Header) error {
	if err := validateHeaderNames(headers); err != nil {
		return err
	}
	resolved := make(http.Header, len(headers))
	for _, name := range slices.Sorted(maps.Keys(headers)) {
		values, err := headers[name].resolve()
		if err != nil {
			return fmt.Errorf("headers[%q]: %w", name, err)
		}
		if len(values) > 0 {
			resolved[http.CanonicalHeaderKey(name)] = values
		}
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	for name := range req.Header {
		if _, ok := resolved[http.CanonicalHeaderKey(name)]; ok {
			delete(req.Header, name)
		}
	}
	maps.Copy(req.Header, resolved)
	return nil
}
