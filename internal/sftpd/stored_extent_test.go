//go:build edi

// Run file-scoped via edi/test.sh only; package-mode -tags edi contaminates globals.
// Copyright (C) 2026 EDI Platform contributors
// SPDX-License-Identifier: AGPL-3.0-only
package sftpd

import (
	"math"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
	"github.com/sftpgo/sdk"
)

type extentFS struct {
	vfs.Fs
	name string
}

func (f extentFS) Name() string { return f.name }

type extentWriter struct{ writes atomic.Int64 }

func (w *extentWriter) WriteAt(p []byte, _ int64) (int, error) { w.writes.Add(1); return len(p), nil }
func (w *extentWriter) Close() error                           { return nil }

func extentTransfer(limit int64, name string) (*transfer, *extentWriter, *atomic.Int64) {
	user := dataprovider.User{BaseUser: sdk.BaseUser{Username: "extent"}}
	user.Filters.MaxUploadFileSize = limit
	conn := common.NewBaseConnection("extent", common.ProtocolSFTP, "", "", user)
	cancelled := &atomic.Int64{}
	base := common.NewBaseTransfer(nil, conn, func() { cancelled.Add(1) }, "file", "file", "/file", common.TransferUpload, 0, 0, 0, 0, true, extentFS{Fs: vfs.NewOsFs("extent", "", "", nil), name: name}, dataprovider.TransferQuota{})
	writer := &extentWriter{}
	return &transfer{BaseTransfer: base, writerAt: writer}, writer, cancelled
}

func TestStoredExtentPrewriteAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		offset  int64
		size    int
		allowed bool
	}{
		{"last_byte", 63, 1, true}, {"boundary_empty", 64, 0, true}, {"past_empty", 65, 0, false},
		{"first_excess", 64, 1, false}, {"sparse", 128, 1, false}, {"negative", -1, 1, false},
		{"wrapped", math.MinInt64, 1, false}, {"maxint", math.MaxInt64, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, w, cancelled := extentTransfer(64, "S3Fs bucket \"test\"")
			n, err := tr.WriteAt(make([]byte, tc.size), tc.offset)
			if tc.offset >= 0 && tr.BytesReceived.Load() != int64(tc.size) {
				t.Fatalf("received packet not counted: %d", tr.BytesReceived.Load())
			}
			if tc.allowed {
				if err != nil || n != tc.size || w.writes.Load() != 1 || cancelled.Load() != 0 {
					t.Fatalf("valid write refused: n=%d err=%v writes=%d cancels=%d", n, err, w.writes.Load(), cancelled.Load())
				}
			} else if err == nil || n != 0 || w.writes.Load() != 0 || cancelled.Load() != 1 || tr.ErrTransfer == nil {
				t.Fatalf("invalid write reached writer or failed to poison: n=%d err=%v writes=%d cancels=%d", n, err, w.writes.Load(), cancelled.Load())
			}
		})
	}
}

func TestStoredExtentScopeAndConcurrentCancellation(t *testing.T) {
	for _, tc := range []struct {
		limit int64
		fs    string
	}{{0, "S3Fs bucket \"test\""}, {64, "OSFs"}} {
		tr, w, cancelled := extentTransfer(tc.limit, tc.fs)
		if n, err := tr.WriteAt([]byte("x"), 128); err != nil || n != 1 || w.writes.Load() != 1 || cancelled.Load() != 0 {
			t.Fatalf("uncapped/other fs changed: %v", err)
		}
	}
	tr, w, cancelled := extentTransfer(64, "S3Fs bucket \"folder\"")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			off := int64(i)
			if i%2 == 0 {
				off = 64
			}
			_, _ = tr.WriteAt([]byte("x"), off)
		}(i)
	}
	wg.Wait()
	if w.writes.Load() != 8 || cancelled.Load() != 1 || tr.ErrTransfer == nil {
		t.Fatalf("concurrent guard writes=%d cancels=%d", w.writes.Load(), cancelled.Load())
	}
}
