//go:build !nos3

package vfs

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestEDIStagingS3DownloadSuccess(t *testing.T) {
	want := make([]byte, 37)
	for i := range want {
		want[i] = byte(i*7 + 3)
	}
	var parts sync.WaitGroup
	parts.Add(4) // All four worker parts must be downloading concurrently.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var start, end int
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if start != 0 {
			parts.Done()
			parts.Wait()
		}
		// The SDK completes part 0 before starting workers. Delay the first
		// worker part too, so later parts reach the real pipe out of order.
		if start == 0 || start == 8 {
			time.Sleep(50 * time.Millisecond)
		}
		end = min(end, len(want)-1)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(want)))
		w.Header().Set("Content-Length", fmt.Sprint(end-start+1))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(want[start : end+1])
	})
	cfg := retryTestConfig()
	cfg.HTTPClient = stagingHTTPClient{handler: handler}
	fs := &S3Fs{config: &S3FsConfig{}, ctxTimeout: time.Second, svc: s3.NewFromConfig(cfg, func(o *s3.Options) { o.BaseEndpoint = aws.String("http://s3.invalid"); o.UsePathStyle = true })}
	fs.config.Bucket = "bucket"
	fs.localTempDir = t.TempDir()
	fs.config.DownloadPartSize = 8
	fs.config.DownloadConcurrency = 4
	before := stagingCounter(t)
	_, r, cancel, err := fs.Open("object", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("download=%x err=%v, want %x and no error", got, err, want)
	}
	if delta := stagingCounter(t) - before; delta != 0 {
		t.Errorf("counter delta=%v, want 0", delta)
	}
}

func TestEDIStagingS3Download(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var start, end int
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if end > 23 {
			end = 23
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/24", start, end))
		w.Header().Set("Content-Length", fmt.Sprint(end-start+1))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(make([]byte, end-start+1))
	})
	cfg := retryTestConfig()
	cfg.HTTPClient = stagingHTTPClient{handler: handler}
	fs := &S3Fs{config: &S3FsConfig{}, ctxTimeout: time.Second, svc: s3.NewFromConfig(cfg, func(o *s3.Options) { o.BaseEndpoint = aws.String("http://s3.invalid"); o.UsePathStyle = true })}
	fs.config.Bucket = "bucket"
	fs.localTempDir = t.TempDir()
	fs.config.DownloadPartSize = 8
	fs.config.DownloadConcurrency = 2
	settled := make(chan struct{})
	original := stagingPipeInDir
	stagingPipeInDir = func(dir string) (pipeReaderAt, pipeWriterAt, error) {
		r, w, err := original(dir)
		return r, &stagingS3FaultWriter{pipeWriterAt: w, settled: settled}, err
	}
	defer func() { stagingPipeInDir = original }()
	before := stagingCounter(t)
	_, r, cancel, err := fs.Open("object", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	defer r.Close()
	_, err = io.Copy(io.Discard, r)
	r.Close()
	<-settled
	if !errors.Is(err, ErrStagingWrite) {
		t.Fatalf("download error=%v, want staging failure, not EOF", err)
	}
	if delta := stagingCounter(t) - before; delta != 1 {
		t.Fatalf("counter delta=%v", delta)
	}
}

type stagingS3FaultWriter struct {
	pipeWriterAt
	settled chan struct{}
}

func (w *stagingS3FaultWriter) CloseWithError(err error) error {
	defer close(w.settled)
	return w.pipeWriterAt.CloseWithError(err)
}

func (w *stagingS3FaultWriter) WriteAt(p []byte, off int64) (int, error) {
	if off >= 8 {
		return 0, io.EOF
	}
	return w.pipeWriterAt.WriteAt(p, off)
}

// Keep SDK request serialization, range dispatch, retries and response parsing;
// only replace the socket boundary, which cannot bind in the offline sandbox.
type stagingHTTPClient struct{ handler http.Handler }

func (c stagingHTTPClient) Do(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	c.handler.ServeHTTP(w, r)
	return w.Result(), nil
}
