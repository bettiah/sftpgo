// Copyright (C) 2026 EDI Platform contributors
// SPDX-License-Identifier: AGPL-3.0-only
package vfs

import (
	"errors"
	"io"
	"sync/atomic"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/metric"
	"github.com/eikenb/pipeat"
)

// ErrStagingWrite means staging I/O failed or a read ended before the written
// extent. pipeat can lose the underlying errno, so this is not specifically ENOSPC.
var ErrStagingWrite = errors.New("temporary staging I/O failed")

var stagingPipeInDir = func(dir string) (pipeReaderAt, pipeWriterAt, error) {
	return pipeat.PipeInDir(dir)
}

type stagingPipeState struct {
	readerClosed atomic.Bool
	writerClosed atomic.Bool
	failed       atomic.Bool
	writtenEnd   atomic.Int64
}

func (s *stagingPipeState) fail() {
	if s.failed.CompareAndSwap(false, true) {
		metric.AddStagingError()
		logger.Error("staging", "", "%v", ErrStagingWrite)
	}
}

type stagingReader struct {
	pipeReaderAt
	state      *stagingPipeState
	readOffset int64 // Sequential Read cursor; ReadAt does not advance it.
}

func (r *stagingReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if r.state.failed.Load() {
		return 0, ErrStagingWrite
	}
	n, err := r.pipeReaderAt.ReadAt(p, off)
	return r.readResult(n, err, off)
}

func (r *stagingReader) readResult(n int, err error, off int64) (int, error) {
	// While the writer is open, pipeat preserves raw file read errors.
	if err != nil && err != io.EOF && !r.state.readerClosed.Load() && !r.state.writerClosed.Load() {
		r.state.fail()
	}
	// After a clean writer close pipeat masks file read errors as EOF. Bytes
	// already written must remain readable; cancellation is not a disk failure.
	if err == io.EOF && !r.state.readerClosed.Load() && off+int64(n) < r.state.writtenEnd.Load() {
		r.state.fail()
	}
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
	off := r.readOffset
	r.readOffset += int64(n)
	return r.readResult(n, err, off)
}

func (r *stagingReader) Close() error { return r.CloseWithError(nil) }
func (r *stagingReader) CloseWithError(err error) error {
	r.state.readerClosed.Store(true)
	return r.pipeReaderAt.CloseWithError(err)
}

type stagingWriter struct {
	pipeWriterAt
	state       *stagingPipeState
	writeOffset int64 // Sequential Write cursor; WriteAt does not advance it.
}

func (w *stagingWriter) writeResult(n int, err error, off int64) (int, error) {
	if n > 0 {
		end := off + int64(n)
		for old := w.state.writtenEnd.Load(); end > old; old = w.state.writtenEnd.Load() {
			if w.state.writtenEnd.CompareAndSwap(old, end) {
				break
			}
		}
	}
	// WriteAt hides file errors as EOF; sequential Write retains the file error.
	if err != nil && !w.state.readerClosed.Load() && !w.state.writerClosed.Load() {
		w.state.fail()
		return 0, ErrStagingWrite
	}
	return n, err
}
func (w *stagingWriter) WriteAt(p []byte, off int64) (int, error) {
	n, err := w.pipeWriterAt.WriteAt(p, off)
	return w.writeResult(n, err, off)
}
func (w *stagingWriter) Write(p []byte) (int, error) {
	n, err := w.pipeWriterAt.Write(p)
	off := w.writeOffset
	w.writeOffset += int64(n)
	return w.writeResult(n, err, off)
}
func (w *stagingWriter) Close() error { return w.CloseWithError(nil) }
func (w *stagingWriter) CloseWithError(err error) error {
	w.state.writerClosed.Store(true)
	return w.pipeWriterAt.CloseWithError(err)
}
