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

package pipeline

import (
	"fmt"
	"math"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// RetryConfig holds retry policy settings.
type RetryConfig struct {
	InitialInterval time.Duration `mapstructure:"initial_interval"`
	MaxInterval     time.Duration `mapstructure:"max_interval"`
	MaxAttempts     int           `mapstructure:"max_attempts"`
	Multiplier      float64       `mapstructure:"multiplier"`
}

// Validate checks that retry settings are not explicitly invalid.
// Zero values are valid and mean "use default" (applied by ApplyDefaults).
func (r *RetryConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if r.MaxAttempts <= 0 {
		errs.Add("max_attempts", fmt.Sprintf("must be > 0, got %d", r.MaxAttempts))
	}
	if r.InitialInterval <= 0 {
		errs.Add("initial_interval", fmt.Sprintf("must be > 0, got %v", r.InitialInterval))
	}
	if r.MaxInterval <= 0 {
		errs.Add("max_interval", fmt.Sprintf("must be > 0, got %v", r.MaxInterval))
	}
	if r.Multiplier <= 0 {
		errs.Add("multiplier", fmt.Sprintf("must be > 0, got %f", r.Multiplier))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ComputeBackoff returns the wait duration for the given attempt number.
func (r *RetryConfig) ComputeBackoff(attempt int) time.Duration {
	interval := float64(r.InitialInterval) * math.Pow(r.Multiplier, float64(attempt-1))
	if time.Duration(interval) > r.MaxInterval {
		return r.MaxInterval
	}
	return time.Duration(interval)
}
