package config_test

import (
	"github.com/drakkan/sftpgo/v2/internal/config"
	"os"
	"path/filepath"
	"testing"
)

func TestEDILimitDefaultsAndEnv(t *testing.T) {
	config.Init()
	t.Cleanup(config.Init)
	if config.GetSFTPDConfig().HandshakeTimeout != 120 || config.GetCommonConfig().MaxTotalTransfers != 0 {
		t.Fatal("wrong compatibility defaults")
	}
	t.Setenv("SFTPGO_SFTPD__HANDSHAKE_TIMEOUT", "30")
	t.Setenv("SFTPGO_COMMON__MAX_TOTAL_TRANSFERS", "24")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "limits.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := config.LoadConfig(dir, "limits.json"); err != nil {
		t.Fatal(err)
	}
	if got := config.GetSFTPDConfig().HandshakeTimeout; got != 30 {
		t.Fatalf("handshake env=%d", got)
	}
	if got := config.GetCommonConfig().MaxTotalTransfers; got != 24 {
		t.Fatalf("transfer env=%d", got)
	}
}
