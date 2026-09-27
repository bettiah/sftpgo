// Copyright (C) 2026 EDI Platform contributors
// SPDX-License-Identifier: AGPL-3.0-only
package vfs

import (
	"bytes"
	"errors"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/rs/zerolog"
	"io"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/eikenb/pipeat"
	"github.com/prometheus/client_golang/prometheus"
)

type stagingFaultWriter struct {
	pipeWriterAt
	fail    bool
	failure error
}

func (w *stagingFaultWriter) WriteAt(p []byte, off int64) (int, error) {
	if w.fail {
		if w.failure != nil {
			return 0, w.failure
		}
		return 0, io.EOF
	}
	return w.pipeWriterAt.WriteAt(p, off)
}
func (w *stagingFaultWriter) Write(p []byte) (int, error) {
	if w.fail {
		if w.failure != nil {
			return 0, w.failure
		}
		return 0, io.EOF
	}
	return w.pipeWriterAt.Write(p)
}
func stagingCounter(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "sftpgo_staging_errors_total" {
			if len(f.Metric) != 1 || len(f.Metric[0].Label) != 0 {
				t.Fatal("staging metric must be unlabelled")
			}
			return f.Metric[0].GetCounter().GetValue()
		}
	}
	t.Fatal("missing staging counter")
	return 0
}
func stagingFaultPipe(t *testing.T) (pipeReaderAt, pipeWriterAt, *stagingFaultWriter) {
	t.Helper()
	original := stagingPipeInDir
	var fault *stagingFaultWriter
	stagingPipeInDir = func(dir string) (pipeReaderAt, pipeWriterAt, error) {
		r, w, err := pipeat.PipeInDir(dir)
		fault = &stagingFaultWriter{pipeWriterAt: w}
		return r, fault, err
	}
	t.Cleanup(func() { stagingPipeInDir = original })
	r, w, err := createPipeFn(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return r, w, fault
}

func TestEDIStagingHoleAndStickyFailure(t *testing.T) {
	for _, sequential := range []bool{false, true} {
		t.Run(map[bool]string{false: "ReadAt", true: "Read"}[sequential], func(t *testing.T) {
			r, w, fault := stagingFaultPipe(t)
			before := stagingCounter(t)
			if _, err := w.WriteAt([]byte("later part"), 10); err != nil {
				t.Fatal(err)
			}
			fault.fail = true
			for i := 0; i < 3; i++ {
				if _, err := w.WriteAt(make([]byte, 10), 0); !errors.Is(err, ErrStagingWrite) {
					t.Errorf("write error = %v", err)
				}
			}
			// Even if a subsequent retry repairs the hole, this pipe stays failed.
			fault.fail = false
			if _, err := w.WriteAt(make([]byte, 10), 0); err != nil {
				t.Fatal(err)
			}
			go w.Close()
			var n int
			var err error
			if sequential {
				n, err = r.Read(make([]byte, 20))
			} else {
				n, err = r.ReadAt(make([]byte, 20), 0)
			}
			if n != 0 || !errors.Is(err, ErrStagingWrite) {
				t.Fatalf("corrupt download exposed: n=%d err=%v", n, err)
			}
			if delta := stagingCounter(t) - before; delta != 1 {
				t.Fatalf("counter delta=%v, want 1", delta)
			}
		})
	}
}

func TestEDIStagingHoleAfterBlockedRead(t *testing.T) {
	for _, sequential := range []bool{false, true} {
		t.Run(map[bool]string{false: "ReadAt", true: "Read"}[sequential], func(t *testing.T) {
			innerR, innerW, err := pipeat.PipeInDir(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan struct{})
			state := &stagingPipeState{}
			r := &stagingReader{pipeReaderAt: &stagingReadBarrier{pipeReaderAt: innerR, entered: entered}, state: state}
			w := &stagingWriter{pipeWriterAt: &stagingFaultWriter{pipeWriterAt: innerW, fail: true}, state: state}
			defer r.Close()
			done := make(chan error, 1)
			go func() {
				var n int
				var err error
				if sequential {
					n, err = r.Read(make([]byte, 10))
				} else {
					n, err = r.ReadAt(make([]byte, 10), 0)
				}
				if n != 0 || !errors.Is(err, ErrStagingWrite) {
					done <- errors.New("blocked read exposed data/EOF")
				} else {
					done <- nil
				}
			}()
			<-entered
			innerW.WriteAt([]byte("later part"), 10)
			_, err = w.WriteAt(make([]byte, 10), 0)
			go w.CloseWithError(err)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

type stagingReadBarrier struct {
	pipeReaderAt
	entered chan struct{}
	once    sync.Once
}

func (r *stagingReadBarrier) ReadAt(p []byte, off int64) (int, error) {
	r.once.Do(func() { close(r.entered) })
	return r.pipeReaderAt.ReadAt(p, off)
}
func (r *stagingReadBarrier) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	return r.pipeReaderAt.Read(p)
}

func TestEDIStagingClosureAndSuccessControls(t *testing.T) {
	for _, closeSide := range []string{"reader", "writer", "reader-error", "writer-error", "success"} {
		t.Run(closeSide, func(t *testing.T) {
			r, w, err := createPipeFn(t.TempDir(), 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { r.Close(); w.Close() }()
			before := stagingCounter(t)
			want := io.EOF
			switch closeSide {
			case "reader":
				r.Close()
			case "writer":
				go w.Close()
				r.ReadAt(make([]byte, 1), 0)
			case "reader-error":
				want = errors.New("cancelled")
				r.CloseWithError(want)
			case "writer-error":
				want = errors.New("cancelled")
				go w.CloseWithError(want)
				r.ReadAt(make([]byte, 1), 0)
			case "success":
				want = nil
			}
			_, err = w.WriteAt([]byte("ok"), 0)
			if !errors.Is(err, want) {
				t.Fatalf("write error=%v want %v", err, want)
			}
			if closeSide == "success" {
				go w.Close()
				if n, err := r.Read(make([]byte, 1)); n != 1 || err != nil {
					t.Fatalf("initial sequential read: n=%d err=%v", n, err)
				}
				b, err := io.ReadAll(r)
				if err != nil || string(b) != "k" {
					t.Fatalf("%q %v", b, err)
				}
			}
			if stagingCounter(t) != before {
				t.Fatal("normal close/success counted as staging failure")
			}
		})
	}
}

func TestEDIStagingConcurrentFailureLogsOnce(t *testing.T) {
	r, w, fault := stagingFaultPipe(t)
	fault.fail = true
	var logs bytes.Buffer
	old := *logger.GetLogger()
	*logger.GetLogger() = zerolog.New(&logs).Level(zerolog.ErrorLevel)
	defer func() { *logger.GetLogger() = old }()
	before := stagingCounter(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := w.WriteAt([]byte("x"), 0); !errors.Is(err, ErrStagingWrite) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	r.Close()
	if delta := stagingCounter(t) - before; delta != 1 {
		t.Fatalf("counter delta=%v", delta)
	}
	if n := strings.Count(logs.String(), `"level":"error"`); n != 1 {
		t.Fatalf("Error logs=%d: %s", n, logs.String())
	}
}

func TestEDIStagingSequentialWriteFailure(t *testing.T) {
	r, w, fault := stagingFaultPipe(t)
	fault.fail = true
	fault.failure = errors.New("injected disk write error")
	before := stagingCounter(t)
	if _, err := w.Write([]byte("bytes")); !errors.Is(err, ErrStagingWrite) {
		t.Fatalf("sequential staging write=%v", err)
	}
	if n, err := r.Read(make([]byte, 5)); n != 0 || !errors.Is(err, ErrStagingWrite) {
		t.Fatalf("read after sequential failure: %d %v", n, err)
	}
	if delta := stagingCounter(t) - before; delta != 1 {
		t.Fatalf("counter delta=%v", delta)
	}
}

// Reader.Close may block on pipeat's file lock while a writer is in flight.
// The closure flag must be published before entering that inner close.
func TestEDIStagingReaderCloseOrder(t *testing.T) {
	original := stagingPipeInDir
	entered, unblock := make(chan struct{}), make(chan struct{})
	stagingPipeInDir = func(dir string) (pipeReaderAt, pipeWriterAt, error) {
		r, w, err := pipeat.PipeInDir(dir)
		return &stagingClosingReader{pipeReaderAt: r, entered: entered, unblock: unblock}, &stagingFaultWriter{pipeWriterAt: w, fail: true}, err
	}
	defer func() { stagingPipeInDir = original }()
	r, w, err := createPipeFn(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); r.Close() }()
	defer func() { close(unblock); <-done; w.Close() }()
	<-entered
	before := stagingCounter(t)
	if _, err := w.WriteAt([]byte("x"), 0); err != io.EOF {
		t.Fatalf("reader cancellation classified as staging failure: %v", err)
	}
	if stagingCounter(t) != before {
		t.Fatal("reader cancellation incremented staging counter")
	}
}

type stagingClosingReader struct {
	pipeReaderAt
	entered, unblock chan struct{}
}

func (r *stagingClosingReader) CloseWithError(err error) error {
	close(r.entered)
	<-r.unblock
	return r.pipeReaderAt.CloseWithError(err)
}

// Model pipeat masking a disk read error with the clean writer's io.EOF.
type stagingShortReader struct {
	pipeReaderAt
	fail    bool
	failure error
}

func (r *stagingShortReader) ReadAt(p []byte, off int64) (int, error) {
	if r.fail {
		if r.failure != nil {
			return 0, r.failure
		}
		return 0, io.EOF
	}
	return r.pipeReaderAt.ReadAt(p, off)
}
func (r *stagingShortReader) Read(p []byte) (int, error) {
	if r.fail {
		if r.failure != nil {
			return 1, r.failure
		}
		return 1, io.EOF // A partial read must discard its bytes too.
	}
	return r.pipeReaderAt.Read(p)
}

// Model Linux rejecting an overflowing pread even when the host returns EOF.
type stagingOverflowReader struct {
	pipeReaderAt
	overflowCalls int
}

func (r *stagingOverflowReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= 0 && int64(len(p)) > math.MaxInt64-off {
		r.overflowCalls++
		return 0, errors.New("injected overflowing read error")
	}
	return r.pipeReaderAt.ReadAt(p, off)
}

func TestEDIStagingInvalidReadOffset(t *testing.T) {
	for _, mode := range []string{"real", "shim"} {
		t.Run(mode, func(t *testing.T) {
			var fault *stagingOverflowReader
			if mode == "shim" {
				original := stagingPipeInDir
				stagingPipeInDir = func(dir string) (pipeReaderAt, pipeWriterAt, error) {
					r, w, err := pipeat.PipeInDir(dir)
					fault = &stagingOverflowReader{pipeReaderAt: r}
					return fault, w, err
				}
				t.Cleanup(func() { stagingPipeInDir = original })
			}
			r, w, err := createPipeFn(t.TempDir(), 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { r.Close(); w.Close() }()
			want := []byte("hello")
			// Leave one extra byte: pipeat waits at the exact extent while the writer is open.
			if _, err := w.WriteAt([]byte("hello!"), 0); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			old := *logger.GetLogger()
			*logger.GetLogger() = zerolog.New(&logs).Level(zerolog.ErrorLevel)
			defer func() { *logger.GetLogger() = old }()
			before := stagingCounter(t)
			buf := make([]byte, 32768)
			for _, off := range []int64{math.MinInt64, -1, math.MaxInt64, math.MaxInt64 - int64(len(buf)) + 1} {
				if n, err := r.ReadAt(buf, off); n != 0 || err == nil || errors.Is(err, ErrStagingWrite) {
					t.Errorf("invalid offset %d: n=%d err=%v, want ordinary error", off, n, err)
				}
			}
			buf = buf[:len(want)]
			if n, err := r.ReadAt(buf, 0); n != len(want) || err != nil || !bytes.Equal(buf, want) {
				t.Errorf("subsequent read: n=%d data=%x err=%v, want %x", n, buf, err, want)
			}
			if delta := stagingCounter(t) - before; delta != 0 {
				t.Errorf("counter delta=%v, want 0", delta)
			}
			if logs.Len() != 0 {
				t.Errorf("unexpected Error log: %s", logs.String())
			}
			if fault != nil && fault.overflowCalls != 0 {
				t.Errorf("overflowing reads reached inner reader: %d", fault.overflowCalls)
			}
		})
	}
}

func TestEDIStagingReadErrorWhileWriting(t *testing.T) {
	for _, sequential := range []bool{false, true} {
		t.Run(map[bool]string{false: "ReadAt", true: "Read"}[sequential], func(t *testing.T) {
			fault := &stagingShortReader{fail: true, failure: errors.New("injected disk read error")}
			r := &stagingReader{pipeReaderAt: fault, state: &stagingPipeState{}}
			var logs bytes.Buffer
			old := *logger.GetLogger()
			*logger.GetLogger() = zerolog.New(&logs).Level(zerolog.ErrorLevel)
			defer func() { *logger.GetLogger() = old }()
			before := stagingCounter(t)
			for i := 0; i < 3; i++ {
				var n int
				var err error
				if sequential {
					n, err = r.Read(make([]byte, 8))
				} else {
					n, err = r.ReadAt(make([]byte, 8), 0)
				}
				if n != 0 || !errors.Is(err, ErrStagingWrite) {
					t.Errorf("staging read: n=%d err=%v", n, err)
				}
			}
			if delta := stagingCounter(t) - before; delta != 1 {
				t.Errorf("counter delta=%v, want 1", delta)
			}
			if n := strings.Count(logs.String(), `"level":"error"`); n != 1 {
				t.Errorf("Error logs=%d: %s", n, logs.String())
			}
		})
	}
}

func TestEDIStagingPrematureEOF(t *testing.T) {
	for _, sequential := range []bool{false, true} {
		t.Run(map[bool]string{false: "ReadAt", true: "Read"}[sequential], func(t *testing.T) {
			original := stagingPipeInDir
			var fault *stagingShortReader
			stagingPipeInDir = func(dir string) (pipeReaderAt, pipeWriterAt, error) {
				r, w, err := pipeat.AsyncWriterPipeInDir(dir)
				fault = &stagingShortReader{pipeReaderAt: r}
				return fault, w, err
			}
			t.Cleanup(func() { stagingPipeInDir = original })
			r, w, err := createPipeFn(t.TempDir(), 0)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			before := stagingCounter(t)
			if sequential {
				if _, err := w.Write([]byte("abcd")); err != nil {
					t.Fatal(err)
				}
				_, err = w.Write([]byte("efgh"))
			} else {
				// The last write is below the high-water mark, as in multipart S3.
				if _, err := w.WriteAt([]byte("efgh"), 4); err != nil {
					t.Fatal(err)
				}
				_, err = w.WriteAt([]byte("abcd"), 0)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			// Legitimate EOF at or beyond the extent must not poison the pipe.
			for _, off := range []int64{0, 8, 12} {
				n, err := r.ReadAt(make([]byte, 16), off)
				want := 0
				if off == 0 {
					want = 8
				}
				if n != want || err != io.EOF {
					t.Fatalf("normal EOF at %d: n=%d err=%v", off, n, err)
				}
			}
			if sequential {
				if n, err := r.Read(make([]byte, 4)); n != 4 || err != nil {
					t.Fatalf("initial read: n=%d err=%v", n, err)
				}
			}
			if stagingCounter(t) != before {
				t.Fatal("normal EOF classified as a staging failure")
			}
			fault.fail = true
			var n int
			if sequential {
				n, err = r.Read(make([]byte, 8))
			} else {
				n, err = r.ReadAt(make([]byte, 8), 6)
			}
			if n != 0 || !errors.Is(err, ErrStagingWrite) {
				t.Fatalf("premature EOF exposed: n=%d err=%v", n, err)
			}
			fault.fail = false
			if n, err := r.ReadAt(make([]byte, 1), 0); n != 0 || !errors.Is(err, ErrStagingWrite) {
				t.Fatalf("read failure was not sticky: n=%d err=%v", n, err)
			}
			if delta := stagingCounter(t) - before; delta != 1 {
				t.Fatalf("read failure counter delta=%v, want 1", delta)
			}
		})
	}
}

func TestEDIStagingReadCancellation(t *testing.T) {
	innerR, innerW, err := pipeat.AsyncWriterPipeInDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := &stagingPipeState{}
	r := &stagingReader{pipeReaderAt: innerR, state: state}
	w := &stagingWriter{pipeWriterAt: innerW, state: state}
	if _, err := w.WriteAt([]byte("unread"), 0); err != nil {
		t.Fatal(err)
	}
	w.Close()
	r.Close()
	before := stagingCounter(t)
	if n, err := r.ReadAt(make([]byte, 1), 0); n != 0 || err != io.EOF {
		t.Fatalf("reader cancellation classified as staging failure: n=%d err=%v", n, err)
	}
	if stagingCounter(t) != before {
		t.Fatal("reader cancellation incremented staging counter")
	}
}
