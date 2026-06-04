package zenet

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// requestsCount is the number of DNS requests answered from the backend.
	requestsCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "requests_total",
		Help:      "Counter of DNS requests answered from the backend.",
	}, []string{"server", "qtype"})
	// errorsCount is the number of requests that failed, by error type.
	errorsCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "errors_total",
		Help:      "Counter of requests that failed, by error type.",
	}, []string{"server", "type"})
	// droppedCount is the number of requests rejected because max_concurrent was exceeded.
	droppedCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "dropped_total",
		Help:      "Counter of requests rejected because max_concurrent was exceeded.",
	}, []string{"server"})
	// nxdomainCount is the number of requests the backend answered with NXDOMAIN.
	nxdomainCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "nxdomain_total",
		Help:      "Counter of requests the backend answered with NXDOMAIN.",
	}, []string{"server"})
	// nodataCount is the number of requests for which the backend returned no records.
	nodataCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "nodata_total",
		Help:      "Counter of requests for which the backend returned no records.",
	}, []string{"server"})
	// requestDuration is the round-trip time of backend requests.
	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "request_duration_seconds",
		Buckets:   plugin.TimeBuckets,
		Help:      "Histogram of backend request round-trip time.",
	}, []string{"server"})
)

// Registry-mode metrics. The registration listener is not a CoreDNS server
// block, so these carry no "server" label.
var (
	// registrationsCount is the number of accepted registry operations.
	// Heartbeats are counted as "register".
	registrationsCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "registrations_total",
		Help:      "Counter of accepted registry operations, by operation.",
	}, []string{"op"})
	// registryErrorsCount is the number of rejected registry messages, by
	// protocol error code.
	registryErrorsCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "registry_errors_total",
		Help:      "Counter of rejected registry messages, by protocol error code.",
	}, []string{"error"})
	// registryNames is the current number of registered service names.
	registryNames = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "registry_names",
		Help:      "Gauge of currently registered service names.",
	})
	// registryEndpoints is the current number of registered endpoints.
	registryEndpoints = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "registry_endpoints",
		Help:      "Gauge of currently registered endpoints across all names.",
	})
	// expirationsCount is the number of endpoints reclaimed by the sweeper.
	expirationsCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "expirations_total",
		Help:      "Counter of endpoints whose lease expired and were reclaimed.",
	})
	// discoverCount is the number of discovery lookups, by source: "rpc" for
	// protocol discover messages, "dns" for DNS queries served from the store.
	discoverCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "discover_total",
		Help:      "Counter of discovery lookups, by source (rpc or dns).",
	}, []string{"source"})
)
