//go:build edi

// Run file-scoped via edi/test.sh only; package-mode -tags edi contaminates globals.
package sftpd

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
	"github.com/pkg/sftp"
	"github.com/sftpgo/sdk"
)

// ediSFTPClient serves one in-memory SFTP session from a loopback client; drop
// closes the transport and waits until the server has closed its open handles.
func ediSFTPClient(t *testing.T, username string, maxSessions int, dir string) (*sftp.Client, func()) {
	t.Helper()
	user := dataprovider.User{BaseUser: sdk.BaseUser{Username: username, HomeDir: dir, Status: 1, MaxSessions: maxSessions, Permissions: map[string][]string{"/": {dataprovider.PermAny}}}}
	c := &Connection{BaseConnection: common.NewBaseConnection("cap", common.ProtocolSFTP, "127.0.0.1:2022", "127.0.0.1:40000", user)}
	serverConn, clientConn := net.Pipe()
	server := sftp.NewRequestServer(serverConn, (&Configuration{}).createHandlers(c))
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); server.Serve() }()
	client, err := sftp.NewClientPipe(clientConn, clientConn)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	drop := func() {
		once.Do(func() { client.Close(); clientConn.Close(); serverConn.Close(); <-done; c.CloseFS() })
	}
	t.Cleanup(drop)
	return client, drop
}

func ediWantFailure(t *testing.T, file *sftp.File, err error) {
	t.Helper()
	if err == nil {
		file.Close()
		t.Fatal("OPEN passed at transfer cap")
	}
	var status *sftp.StatusError
	if !errors.As(err, &status) || status.Code != 4 {
		t.Fatalf("OPEN status=%v, want SSH_FX_FAILURE", err)
	}
}

func TestEDITransferCapSFTPStatusAndRelease(t *testing.T) {
	ediAuthSetup(t, "")
	common.Config.MaxTotalTransfers = 1
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "existing"), []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	client, _ := ediSFTPClient(t, "partner", 0, dir)
	release, err := common.Connections.ReserveTransfer("other", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, write := range []bool{false, true} {
		var file *sftp.File
		if write {
			file, err = client.Create("new")
		} else {
			file, err = client.Open("existing")
		}
		ediWantFailure(t, file, err)
	}
	if _, err := client.Stat("existing"); err != nil {
		t.Fatalf("session unusable after refusal: %v", err)
	}
	ediScore(t, 0)
	release()
	// A failed filesystem OPEN must release the pending reservation too.
	if f, err := client.Open("missing"); err == nil {
		f.Close()
		t.Fatal("missing file opened")
	}
	f, err := client.Open("existing")
	if err != nil {
		t.Fatalf("reservation leaked after failed open: %v", err)
	}
	if common.Connections.GetTotalTransfers() != 1 {
		t.Fatal("active transfer not counted")
	}
	if _, err := client.Create("new"); err == nil {
		t.Fatal("active download did not consume cap")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	f, err = client.Create("new")
	if err != nil {
		t.Fatalf("capacity not restored after CLOSE: %v", err)
	}
	if _, err := f.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if common.Connections.GetTotalTransfers() != 0 {
		t.Fatal("active transfer leaked")
	}
	ediScore(t, 0)
}

// The user's max_sessions also caps its concurrent SFTP handles on this process.
func TestEDIUserTransferCapSFTP(t *testing.T) {
	ediAuthSetup(t, "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "existing"), []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	client, drop := ediSFTPClient(t, "partner", 1, dir)
	// A failed filesystem OPEN must release the per-user reservation.
	if f, err := client.Open("missing"); err == nil {
		f.Close()
		t.Fatal("missing file opened")
	}
	held, err := client.Open("existing")
	if err != nil {
		t.Fatalf("per-user reservation leaked after failed open: %v", err)
	}
	f, err := client.Open("existing")
	ediWantFailure(t, f, err)
	f, err = client.Create("new")
	ediWantFailure(t, f, err)
	if _, err := client.Stat("existing"); err != nil {
		t.Fatalf("session unusable after refusal: %v", err)
	}
	ediScore(t, 0)
	// Control: another capped user is unaffected by partner's handle.
	other, _ := ediSFTPClient(t, "other", 1, dir)
	of, err := other.Open("existing")
	if err != nil {
		t.Fatalf("other user refused by partner's cap: %v", err)
	}
	if err := of.Close(); err != nil {
		t.Fatal(err)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	f, err = client.Create("new")
	if err != nil {
		t.Fatalf("capacity not restored after CLOSE: %v", err)
	}
	if _, err := f.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// Dropping a connection that holds a handle must free the user's slot.
	if _, err := client.Open("existing"); err != nil {
		t.Fatal(err)
	}
	drop()
	again, _ := ediSFTPClient(t, "partner", 1, dir)
	f, err = again.Open("existing")
	if err != nil {
		t.Fatalf("capacity not restored after disconnect: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if common.Connections.GetTotalTransfers() != 0 {
		t.Fatal("active transfer leaked")
	}
	ediScore(t, 0)
}

type ediStagingIO struct{}

func (ediStagingIO) ReadAt([]byte, int64) (int, error)  { return 0, vfs.ErrStagingWrite }
func (ediStagingIO) WriteAt([]byte, int64) (int, error) { return 0, vfs.ErrStagingWrite }
func (ediStagingIO) Close() error                       { return nil }

// Existing generic conversion supplies SSH_FX_FAILURE in both directions. This
// is a compatibility pin for the staging sentinel, including read-side failures.
func TestEDIStagingSFTPMapping(t *testing.T) {
	ediAuthSetup(t, "")
	for _, kind := range []int{common.TransferDownload, common.TransferUpload} {
		user := dataprovider.User{BaseUser: sdk.BaseUser{Username: "partner"}}
		c := common.NewBaseConnection("staging", common.ProtocolSFTP, "", "", user)
		fs := vfs.NewOsFs("staging", t.TempDir(), "", nil)
		base := common.NewBaseTransfer(nil, c, nil, "fixture", "fixture", "/fixture", kind, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
		tr := &transfer{BaseTransfer: base, writerAt: ediStagingIO{}, readerAt: ediStagingIO{}}
		for i := 0; i < 2; i++ {
			var err error
			if kind == common.TransferDownload {
				_, err = tr.ReadAt(make([]byte, 1), 0)
			} else {
				_, err = tr.WriteAt([]byte("x"), 0)
			}
			if !errors.Is(err, sftp.ErrSSHFxFailure) || errors.Is(err, io.EOF) {
				t.Fatalf("staging status=%v", err)
			}
		}
		if err := tr.Close(); !errors.Is(err, sftp.ErrSSHFxFailure) {
			t.Fatalf("CLOSE status=%v", err)
		}
	}
}
