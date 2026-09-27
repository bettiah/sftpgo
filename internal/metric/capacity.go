package metric

// Capacity refusal labels match the corresponding configuration keys.
const (
	CapacityLimitTotalConnections   = "max_total_connections"
	CapacityLimitPerHostConnections = "max_per_host_connections"
	CapacityLimitTotalTransfers     = "max_total_transfers"
)
