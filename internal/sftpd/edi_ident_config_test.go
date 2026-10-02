//go:build edi

// Run file-scoped via edi/test.sh only; package-mode -tags edi contaminates globals.
package sftpd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/config"
	"github.com/drakkan/sftpgo/v2/internal/version"
)

func TestEDIIdentificationFromConfig(t *testing.T) {
	previous := version.GetConfig()
	t.Cleanup(func() { version.SetConfig(previous) })
	t.Cleanup(config.Init)
	// common.Initialize needs a provider for its event scheduler. Use the
	// existing memory-provider fixture without starting any network listeners.
	ediAuthSetup(t, "")
	for _, tc := range []struct{ name, json, env string }{
		{"json", `{"common":{"server_version":"neutral"}}`, ""},
		{"env", `{}`, "neutral"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config.Init()
			t.Setenv("SFTPGO_COMMON__SERVER_VERSION", tc.env)
			// Empty environment values override JSON too; remove the key
			// for the JSON case, with Setenv still restoring the caller's env.
			if tc.env == "" {
				if err := os.Unsetenv("SFTPGO_COMMON__SERVER_VERSION"); err != nil {
					t.Fatal(err)
				}
			}
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "ident.json"), []byte(tc.json), 0600); err != nil {
				t.Fatal(err)
			}
			if err := config.LoadConfig(dir, "ident.json"); err != nil {
				t.Fatal(err)
			}
			// Seed a different value so omitting Initialize's SetConfig call
			// cannot pass by inheriting neutral from an earlier case.
			version.SetConfig("short")
			if err := common.Initialize(config.GetCommonConfig(), 0); err != nil {
				t.Fatal(err)
			}
			serverConfig := (&Configuration{}).getServerConfig()
			if serverConfig.ServerVersion != "SSH-2.0-EDI" {
				t.Fatalf("ServerVersion=%q, want SSH-2.0-EDI", serverConfig.ServerVersion)
			}
		})
	}
}
