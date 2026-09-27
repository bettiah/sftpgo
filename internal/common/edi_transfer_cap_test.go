package common

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func ediConnections(t *testing.T) *ActiveConnections {
	t.Helper()
	old := Config
	t.Cleanup(func() { Config = old })
	Config = Configuration{}
	return &ActiveConnections{clients: clientsMap{clients: map[string]int{}}, transfers: clientsMap{clients: map[string]int{}}}
}
func ediRefusals(t *testing.T, limit string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "sftpgo_capacity_refusals_total" {
			for _, m := range f.Metric {
				if len(m.Label) != 1 || m.Label[0].GetName() != "limit" {
					t.Fatal("capacity metric labels must be limit only")
				}
				switch m.Label[0].GetValue() {
				case "max_total_transfers", "max_total_connections", "max_per_host_connections":
				default:
					t.Fatal("unexpected metric label")
				}
				if m.Label[0].GetValue() == limit {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}
func TestEDITransferReservations(t *testing.T) {
	c := ediConnections(t)
	Config.MaxTotalTransfers = 2
	a, err := c.ReserveTransfer("a")
	if err != nil {
		t.Fatal(err)
	}
	defer a()
	b, err := c.ReserveTransfer("b")
	if err != nil {
		t.Fatal(err)
	}
	defer b()
	before := ediRefusals(t, "max_total_transfers")
	if _, err := c.ReserveTransfer("c"); !errors.Is(err, ErrTransferLimit) {
		t.Fatalf("pending reservations ignored: %v", err)
	}
	if ediRefusals(t, "max_total_transfers")-before != 1 {
		t.Fatal("missing transfer refusal metric")
	}
	// New transfer capacity must never refuse a new SSH/HTTP connection.
	if err := c.IsNewConnectionAllowed("127.0.0.1", ProtocolSSH); err != nil {
		t.Fatal(err)
	}
	a()
	a()
	c.transfers.add("b")
	b() // hand off pending to active
	d, err := c.ReserveTransfer("d")
	if err != nil {
		t.Fatal(err)
	}
	defer d()
	if _, err := c.ReserveTransfer("e"); !errors.Is(err, ErrTransferLimit) {
		t.Fatalf("active+pending undercount: %v", err)
	}
	d()
	c.transfers.remove("b")
	if c.pendingTransfers != 0 {
		t.Fatalf("reservation leak=%d", c.pendingTransfers)
	}
}

// Run with -race: removing the reservation mutex may preserve the count but race.
func TestEDITransferReservationConcurrent(t *testing.T) {
	c := ediConnections(t)
	const cap = 7
	Config.MaxTotalTransfers = cap
	var wg sync.WaitGroup
	var successes atomic.Int32
	start := make(chan struct{})
	releases := make(chan func(), 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			release, err := c.ReserveTransfer("same-user")
			if err == nil {
				successes.Add(1)
				releases <- release
			} else if !errors.Is(err, ErrTransferLimit) {
				t.Error(err)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(releases)
	if successes.Load() != cap {
		t.Errorf("successful reservations=%d want exactly %d", successes.Load(), cap)
	}
	for release := range releases {
		release()
	}
	if c.pendingTransfers != 0 {
		t.Fatal("leaked reservation")
	}
}
func TestEDITransferLegacyLimits(t *testing.T) {
	c := ediConnections(t)
	for _, limit := range []int{0, -1} {
		Config.MaxTotalTransfers = limit
		for i := 0; i < 20; i++ {
			r, err := c.ReserveTransfer("user")
			if err != nil {
				t.Fatal(err)
			}
			defer r()
		}
	}
	Config.MaxTotalConnections = 1
	c.transfers.add("user")
	if _, err := c.ReserveTransfer("other"); !errors.Is(err, ErrConnectionDenied) {
		t.Fatalf("old global error changed: %v", err)
	}
	Config.MaxTotalConnections = 0
	Config.MaxPerHostConnections = 1
	if _, err := c.ReserveTransfer("user"); !errors.Is(err, ErrConnectionDenied) {
		t.Fatalf("old per-user error changed: %v", err)
	}
	if r, err := c.ReserveTransfer("other"); err != nil {
		t.Fatal(err)
	} else {
		r()
	}
	wasShuttingDown := isShuttingDown.Swap(true)
	defer isShuttingDown.Store(wasShuttingDown)
	if _, err := c.ReserveTransfer("other"); !errors.Is(err, ErrShuttingDown) {
		t.Fatal(err)
	}
}
func TestEDICapacityRefusalMetrics(t *testing.T) {
	for _, branch := range []string{"transfer-user", "transfer-total", "clients", "sessions", "active-transfers", "client-host"} {
		t.Run(branch, func(t *testing.T) {
			c := ediConnections(t)
			limit := "max_total_connections"
			Config.MaxTotalConnections = 1
			switch branch {
			case "transfer-user":
				Config.MaxTotalConnections = 0
				Config.MaxPerHostConnections = 1
				c.transfers.add("user")
				limit = "max_per_host_connections"
			case "transfer-total", "active-transfers":
				c.transfers.add("user")
			case "clients":
				c.clients.add("ip")
				c.clients.add("ip")
			case "sessions":
				c.connections = append(c.connections, nil)
			case "client-host":
				Config.MaxTotalConnections = 0
				Config.MaxPerHostConnections = 1
				c.clients.add("ip")
				c.clients.add("ip")
				limit = "max_per_host_connections"
			}
			before := ediRefusals(t, limit)
			var err error
			if branch == "transfer-user" || branch == "transfer-total" {
				err = c.IsNewTransferAllowed("user")
			} else {
				err = c.IsNewConnectionAllowed("ip", ProtocolHTTP)
			}
			if !errors.Is(err, ErrConnectionDenied) {
				t.Fatalf("expected refusal: %v", err)
			}
			if delta := ediRefusals(t, limit) - before; delta != 1 {
				t.Fatalf("%s delta=%v", branch, delta)
			}
		})
	}
}

type ediSafeDefender struct{ Defender }

func (ediSafeDefender) AddEvent(string, string, HostEvent) bool { return true }

func TestEDICapacitySafeHostNotCounted(t *testing.T) {
	c := ediConnections(t)
	Config.defender = ediSafeDefender{}
	Config.MaxPerHostConnections = 1
	c.clients.add("127.0.0.1")
	c.clients.add("127.0.0.1")
	before := ediRefusals(t, "max_per_host_connections")
	if err := c.IsNewConnectionAllowed("127.0.0.1", ProtocolSSH); err != nil {
		t.Fatal(err)
	}
	if ediRefusals(t, "max_per_host_connections") != before {
		t.Fatal("safelisted host counted as refused")
	}
}
