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

package sdk

import (
	"fmt"
	"net/url"
)

// ValidateHosts checks that hosts is non-empty and each entry is a valid URL
// with scheme and host.
func ValidateHosts(name string, hosts []string) error {
	if len(hosts) == 0 {
		return fmt.Errorf("%s: hostport is required", name)
	}
	for _, h := range hosts {
		if h == "" {
			return fmt.Errorf("%s: hostport entry must not be empty", name)
		}
		u, err := url.Parse(h)
		if err != nil {
			return fmt.Errorf("%s: invalid hostport %q: %w", name, h, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("%s: hostport %q must include scheme and host (e.g. http://host:port)", name, h)
		}
	}
	return nil
}
