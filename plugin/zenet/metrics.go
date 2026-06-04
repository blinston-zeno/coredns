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
