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

package reload

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const metricsNamespace = "falcosidekick"

type reloadMetrics struct {
	total       prometheus.Counter
	failures    prometheus.Counter
	partial     prometheus.Counter
	lastSuccess prometheus.Gauge
	duration    prometheus.Histogram
}

// newReloadMetrics constructs and optionally registers the reload metrics.
// A nil registerer skips registration.
func newReloadMetrics(reg prometheus.Registerer) *reloadMetrics {
	m := &reloadMetrics{
		total: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reload_total",
			Help:      "Total output config reload attempts including no-op (success + failure + no-change).",
		}),
		failures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reload_failures_total",
			Help:      "Failed output config reload attempts.",
		}),
		partial: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reload_partial_total",
			Help:      "Reload attempts where runtime apply succeeded but a non-runtime step (e.g. DB sync) failed.",
		}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "reload_last_success_timestamp",
			Help:      "Unix timestamp of last successful reload.",
		}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "reload_duration_seconds",
			Help:      "Duration of reload cycles in seconds.",
			Buckets:   prometheus.DefBuckets,
		}),
	}

	if reg != nil {
		reg.MustRegister(m.total, m.failures, m.partial, m.lastSuccess, m.duration)
	}

	return m
}

func (m *reloadMetrics) recordSuccess(d time.Duration) {
	m.total.Inc()
	m.lastSuccess.SetToCurrentTime()
	m.duration.Observe(d.Seconds())
}

func (m *reloadMetrics) recordPartialSuccess(d time.Duration) {
	m.total.Inc()
	m.partial.Inc()
	m.duration.Observe(d.Seconds())
}

func (m *reloadMetrics) recordFailure(d time.Duration) {
	m.total.Inc()
	m.failures.Inc()
	m.duration.Observe(d.Seconds())
}
