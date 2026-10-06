// Copyright (C) 2026 EDI Platform contributors
// SPDX-License-Identifier: AGPL-3.0-only

package metric

// Capacity refusal labels match the corresponding configuration keys.
const (
	CapacityLimitTotalConnections   = "max_total_connections"
	CapacityLimitPerHostConnections = "max_per_host_connections"
	CapacityLimitTotalTransfers     = "max_total_transfers"
	CapacityLimitMaxSessions        = "max_sessions"
)

// capacityLimits lists every capacity refusal label; each is exported at 0 from startup.
var capacityLimits = []string{
	CapacityLimitTotalConnections,
	CapacityLimitPerHostConnections,
	CapacityLimitTotalTransfers,
	CapacityLimitMaxSessions,
}
