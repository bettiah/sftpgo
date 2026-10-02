//go:build edi

// Run file-scoped via edi/test.sh only; package-mode -tags edi contaminates globals.
package sftpd

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/version"
	"golang.org/x/crypto/ssh"
)

func TestEDIIdentificationWire(t *testing.T) {
	previous := version.GetConfig()
	t.Cleanup(func() { version.SetConfig(previous) })
	for _, tc := range []struct{ setting, want string }{
		{"neutral", "SSH-2.0-EDI\r\n"},
		{"", "SSH-2.0-SFTPGo_" + version.Get().Version + "\r\n"},
		{"short", "SSH-2.0-SFTPGo\r\n"},
	} {
		t.Run(tc.setting, func(t *testing.T) {
			version.SetConfig(tc.setting)
			cfg := ediServerConfig(t, &Configuration{})
			if cfg.ServerVersion+"\r\n" != tc.want {
				t.Errorf("ServerConfig.ServerVersion=%q, want %q", cfg.ServerVersion, tc.want)
			}
			// net.Pipe exercises the SSH wire exchange without binding a local port.
			conn, server := net.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(5 * time.Second))
				_, _, _, _ = ssh.NewServerConn(server, cfg)
			}()
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if line != tc.want {
				t.Errorf("wire identification=%q, want %q", line, tc.want)
			}
			conn.Close()
			<-done
		})
	}
}
