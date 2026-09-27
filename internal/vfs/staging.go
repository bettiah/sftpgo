// Copyright (C) 2026 EDI Platform contributors
// SPDX-License-Identifier: AGPL-3.0-only
package vfs

import (
	"errors"
	"sync/atomic"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/metric"
	"github.com/eikenb/pipeat"
)

// ErrStagingWrite means the staging file could not accept a write. pipeat loses
// the underlying errno, so this must not be classified specifically as ENOSPC.
var ErrStagingWrite = errors.New("temporary staging write failed")

var stagingPipeInDir = func(dir string) (pipeReaderAt, pipeWriterAt, error) {
	return pipeat.PipeInDir(dir)
}

type stagingPipeState struct {
	readerClosed atomic.Bool
	writerClosed atomic.Bool
	failed       atomic.Bool
}

type stagingReader struct {
	pipeReaderAt
	state *stagingPipeState
}

func (r *stagingReader) ReadAt(p []byte, off int64) (int, error) {
	if r.state.failed.Load() {
		return 0, ErrStagingWrite
	}
	n, err := r.pipeReaderAt.ReadAt(p, off)
	// Closing the writer can unblock a read over holes. Discard those bytes even
	// when the underlying read reports success, or a retry subsequently succeeded.
	if r.state.failed.Load() {
		return 0, ErrStagingWrite
	}
	return n, err
}

func (r *stagingReader) Read(p []byte) (int, error) {
	if r.state.failed.Load() {
		return 0, ErrStagingWrite
	}
	n, err := r.pipeReaderAt.Read(p)
	if r.state.failed.Load() {
		return 0, ErrStagingWrite
	}
	return n, err
}

func (r *stagingReader) Close() error { return r.CloseWithError(nil) }
func (r *stagingReader) CloseWithError(err error) error {
	r.state.readerClosed.Store(true)
	return r.pipeReaderAt.CloseWithError(err)
}

type stagingWriter struct {
	pipeWriterAt
	state *stagingPipeState
}

func (w *stagingWriter) writeResult(n int, err error) (int, error) {
	// WriteAt hides file errors as EOF; sequential Write retains the file error.
	if err != nil && !w.state.readerClosed.Load() && !w.state.writerClosed.Load() {
		if w.state.failed.CompareAndSwap(false, true) {
			metric.AddStagingWriteError()
			logger.Error("staging", "", "%v", ErrStagingWrite)
		}
		return 0, ErrStagingWrite
	}
	return n, err
}
func (w *stagingWriter) WriteAt(p []byte, off int64) (int, error) {
	return w.writeResult(w.pipeWriterAt.WriteAt(p, off))
}
func (w *stagingWriter) Write(p []byte) (int, error) {
	return w.writeResult(w.pipeWriterAt.Write(p))
}
func (w *stagingWriter) Close() error { return w.CloseWithError(nil) }
func (w *stagingWriter) CloseWithError(err error) error {
	w.state.writerClosed.Store(true)
	return w.pipeWriterAt.CloseWithError(err)
}
