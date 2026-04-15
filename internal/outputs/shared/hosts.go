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
	"net/url"
	"regexp"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

var endpointRegex = regexp.MustCompile(`^/[\w/.%:@!$&'()*+,;=-]*$`)

// ValidateURL checks that a value is a valid URL with scheme and host.
func ValidateURL(value string) utils.ValidationErrors {
	var errs utils.ValidationErrors
	if value == "" {
		errs.Add("", "is required")
		return errs
	}
	u, err := url.Parse(value)
	if err != nil {
		errs.Add("", fmt.Sprintf("invalid URL %q: %v", value, err))
		return errs
	}
	if u.Scheme == "" || u.Host == "" {
		errs.Add("", fmt.Sprintf("must include scheme and host (e.g. https://host:port), got %q", value))
	}
	return errs
}

// ValidateEndpoint checks that a value is a valid HTTP path.
func ValidateEndpoint(value string) utils.ValidationErrors {
	var errs utils.ValidationErrors
	if value == "" {
		return errs
	}
	if !endpointRegex.MatchString(value) {
		errs.Add("", fmt.Sprintf("must be a valid path starting with / (e.g. /api/v1), got %q", value))
	}
	return errs
}

// ValidateHosts checks that hosts is non-empty and each entry has scheme and host.
func ValidateHosts(hosts []string) utils.ValidationErrors {
	var errs utils.ValidationErrors
	if len(hosts) == 0 {
		errs.Add("", "is required")
		return errs
	}
	for i, h := range hosts {
		if h == "" {
			errs.Add("", fmt.Sprintf("entry [%d] must not be empty", i))
			continue
		}
		u, err := url.Parse(h)
		if err != nil {
			errs.Add("", fmt.Sprintf("entry [%d] invalid URL %q: %v", i, h, err))
			continue
		}
		if u.Scheme == "" || u.Host == "" {
			errs.Add("", fmt.Sprintf("entry [%d] must include scheme and host, got %q", i, h))
		}
	}
	return errs
}
