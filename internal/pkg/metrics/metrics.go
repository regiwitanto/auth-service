package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// RequestCounter counts the number of HTTP requests
	RequestCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_http_requests_total",
			Help: "Total number of HTTP requests by path and status",
		},
		[]string{"path", "method", "status"},
	)

	// RequestDuration measures request duration
	RequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "auth_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"path", "method", "status"},
	)

	// DatabaseOperationsCounter counts the number of database operations
	DatabaseOperationsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_database_operations_total",
			Help: "Total number of database operations by type and status",
		},
		[]string{"operation", "status"},
	)

	// DatabaseOperationsDuration measures database operation duration
	DatabaseOperationsDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "auth_database_operation_duration_seconds",
			Help:    "Database operation duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"operation"},
	)

	// LoginAttemptsCounter counts login attempts
	LoginAttemptsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_login_attempts_total",
			Help: "Total number of login attempts by status",
		},
		[]string{"status"},
	)

	// ActiveTokensGauge tracks the number of active tokens
	ActiveTokensGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "auth_active_tokens",
			Help: "Number of active tokens in the system",
		},
	)

	// SystemGauges for system metrics
	SystemGauges = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "auth_system_info",
			Help: "System information metrics",
		},
		[]string{"name"},
	)

	// InternalErrors counts internal errors
	InternalErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_internal_errors_total",
			Help: "Total number of internal errors by type",
		},
		[]string{"type"},
	)
)

// RecordDBOperation records a database operation
func RecordDBOperation(operation string, err error) {
	status := "success"
	if err != nil {
		status = "error"
	}
	DatabaseOperationsCounter.WithLabelValues(operation, status).Inc()
}

// RecordLoginAttempt records a login attempt
func RecordLoginAttempt(success bool) {
	status := "success"
	if !success {
		status = "failure"
	}
	LoginAttemptsCounter.WithLabelValues(status).Inc()
}

// RecordInternalError records an internal error
func RecordInternalError(errorType string) {
	InternalErrors.WithLabelValues(errorType).Inc()
}
