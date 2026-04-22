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

package api

import (
	"io/fs"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
)

// registerStaticUI installs the static-asset middleware on app when assets
// is non-nil. API and operator paths (/api/**, /healthz, /version, /metrics)
// are always skipped so they remain served by their explicit handlers.
func registerStaticUI(app *fiber.App, assets fs.FS) {
	if assets == nil {
		return
	}
	app.Use(static.New("", static.Config{
		FS:            assets,
		IndexNames:    []string{"index.html"},
		CacheDuration: 10 * time.Second,
		Compress:      true,
		Next:          skipAPIPaths,
	}))
}

func skipAPIPaths(c fiber.Ctx) bool {
	p := c.Path()
	if strings.HasPrefix(p, "/api/") {
		return true
	}
	switch p {
	case "/healthz", "/version", "/metrics":
		return true
	}
	return false
}
