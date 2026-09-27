package sftpd

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
	"github.com/pkg/sftp"
	"github.com/rs/zerolog"
	"github.com/sftpgo/sdk"
)

func TestEDITransferCapSFTPStatusAndRelease(t *testing.T) {
	ediAuthSetup(t, "")
	common.Config.MaxTotalTransfers = 1
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "existing"), []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	user := dataprovider.User{BaseUser: sdk.BaseUser{Username: "partner", HomeDir: dir, Status: 1, Permissions: map[string][]string{"/": {dataprovider.PermAny}}}}
	c := &Connection{BaseConnection: common.NewBaseConnection("cap", common.ProtocolSFTP, "", "", user)}
	defer c.CloseFS()
	serverConn, clientConn := net.Pipe()
	server := sftp.NewRequestServer(serverConn, (&Configuration{}).createHandlers(c))
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); server.Serve() }()
	defer func() { clientConn.Close(); serverConn.Close(); <-done }()
	client, err := sftp.NewClientPipe(clientConn, clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	release, err := common.Connections.ReserveTransfer("other")
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
		if err == nil {
			file.Close()
			t.Fatal("OPEN passed at transfer cap")
		}
		var status *sftp.StatusError
		if !errors.As(err, &status) || status.Code != 4 {
			t.Fatalf("OPEN status=%v, want SSH_FX_FAILURE", err)
		}
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

type ediStagingIO struct{}

func (ediStagingIO) ReadAt([]byte, int64) (int, error)  { return 0, vfs.ErrStagingWrite }
func (ediStagingIO) WriteAt([]byte, int64) (int, error) { return 0, vfs.ErrStagingWrite }
func (ediStagingIO) Close() error                       { return nil }

// Existing generic conversion supplies SSH_FX_FAILURE in both directions. This
// is a compatibility pin; the new guard here is duplicate Error-log suppression.
func TestEDIStagingSFTPMappingAndNoDuplicateLogs(t *testing.T) {
	ediAuthSetup(t, "")
	var logs bytes.Buffer
	old := *logger.GetLogger()
	*logger.GetLogger() = zerolog.New(&logs).Level(zerolog.ErrorLevel)
	defer func() { *logger.GetLogger() = old }()
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
	if logs.Len() != 0 {
		t.Fatalf("staging wrapper's Error log duplicated by transfer: %s", logs.String())
	}
}
