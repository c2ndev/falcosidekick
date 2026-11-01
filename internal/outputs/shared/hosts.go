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

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

var endpointRegex = regexp.MustCompile(`^/[\w/.%:@!$&'()*+,;=-]*$`)

// Validation messages never include the value or url.Parse causes: URLs can carry credentials.

// ValidateURL checks that a value is a valid HTTP(S) URL with scheme and host.
func ValidateURL(value string) utils.ValidationErrors {
	var errs utils.ValidationErrors
	if value == "" {
		errs.Add("", "is required")
		return errs
	}
	if problem := urlProblem(value, true); problem != "" {
		errs.Add("", problem)
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
		errs.Add("", "must be a valid path starting with / (e.g. /api/v1)")
	}
	return errs
}

// ValidateHosts checks that hosts is non-empty and each entry has scheme and host.
func ValidateHosts(hosts []string) utils.ValidationErrors {
	return validateHosts(hosts, false)
}

// ValidateHTTPHosts is ValidateHosts restricted to HTTP(S) schemes.
func ValidateHTTPHosts(hosts []string) utils.ValidationErrors {
	return validateHosts(hosts, true)
}

func validateHosts(hosts []string, httpOnly bool) utils.ValidationErrors {
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
		if problem := urlProblem(h, httpOnly); problem != "" {
			errs.Add("", fmt.Sprintf("entry [%d] %s", i, problem))
		}
	}
	return errs
}

func urlProblem(value string, httpOnly bool) string {
	u, err := url.Parse(value)
	if err != nil {
		return "invalid URL"
	}
	if u.Scheme == "" || u.Host == "" {
		return "must include scheme and host (e.g. https://host:port)"
	}
	if httpOnly && u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS {
		return "scheme must be http or https"
	}
	return ""
}
