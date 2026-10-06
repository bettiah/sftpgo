//go:build edi && !nometrics

// Run file-scoped via edi/test.sh only; this test increments global counters.
package metric_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/drakkan/sftpgo/v2/internal/metric"
)

func TestEDICapacityRefusalsAtStartup(t *testing.T) {
	assertCounters := func(want float64) {
		t.Helper()
		families, err := prometheus.DefaultGatherer.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, family := range families {
			if family.GetName() != "sftpgo_capacity_refusals_total" {
				continue
			}
			missing := map[string]bool{
				"max_total_connections":    true,
				"max_per_host_connections": true,
				"max_total_transfers":      true,
				"max_sessions":             true,
			}
			if len(family.Metric) != len(missing) {
				t.Fatalf("capacity refusal children = %d, want %d", len(family.Metric), len(missing))
			}
			for _, child := range family.Metric {
				if len(child.Label) != 1 || child.Label[0].GetName() != "limit" {
					t.Fatalf("unexpected capacity refusal labels: %v", child.Label)
				}
				limit := child.Label[0].GetValue()
				if !missing[limit] {
					t.Fatalf("unexpected or duplicate capacity refusal limit: %q", limit)
				}
				delete(missing, limit)
				if child.Counter == nil || child.Counter.GetValue() != want {
					t.Fatalf("capacity refusals for %q = %v, want counter %v", limit, child.Counter, want)
				}
			}
			return
		}
		t.Fatal("capacity refusal metric missing at startup")
	}

	assertCounters(0)
	metric.AddCapacityRefusal(metric.CapacityLimitTotalConnections)
	metric.AddCapacityRefusal(metric.CapacityLimitPerHostConnections)
	metric.AddCapacityRefusal(metric.CapacityLimitTotalTransfers)
	metric.AddCapacityRefusal(metric.CapacityLimitMaxSessions)
	assertCounters(1)
}
