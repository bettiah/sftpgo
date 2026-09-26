//go:build !nos3

package vfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

const retryTestError = `<Error><Code>InternalError</Code><Message>injected</Message></Error>`

// Real SDK serialization/deserialization and HTTP transport, with no external AWS
// configuration. Tiny synthetic parts test dispatch, not S3's minimum part size.
func retryTestConfig() aws.Config {
	return aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("fixture", "fixture", ""),
		HTTPClient:  getAWSHTTPClient(5, time.Second, false),
		Retryer: func() aws.Retryer {
			return retry.AddWithMaxAttempts(retry.NewStandard(func(o *retry.StandardOptions) {
				o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
			}), 3)
		},
	}
}

func retryTestFS(t *testing.T, handler http.HandlerFunc) *S3Fs {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	config := &S3FsConfig{}
	config.Bucket = "bucket"
	config.UploadPartSize = 8
	config.UploadPartMaxTime = 5
	config.UploadConcurrency = 1
	return &S3Fs{
		config:     config,
		ctxTimeout: 5 * time.Second,
		svc: s3.NewFromConfig(retryTestConfig(), func(o *s3.Options) {
			o.BaseEndpoint = aws.String(server.URL)
			o.UsePathStyle = true
			o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
			o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		}),
	}
}

func retryTestSuccess(w http.ResponseWriter, operation string) {
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("ETag", `"fixture"`)
	switch operation {
	case "create":
		fmt.Fprint(w, `<InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>key</Key><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>`)
	case "complete":
		fmt.Fprint(w, `<CompleteMultipartUploadResult><Bucket>bucket</Bucket><Key>key</Key><ETag>"fixture"</ETag></CompleteMultipartUploadResult>`)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func retryTestFault(t *testing.T, w http.ResponseWriter, fault string) {
	t.Helper()
	if fault == "drop" {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	if fault != "embedded" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	fmt.Fprint(w, retryTestError)
}

func retryTestInvoke(ctx context.Context, fs *S3Fs, operation string, baseline bool) error {
	parts := []types.CompletedPart{{ETag: aws.String(`"fixture"`), PartNumber: aws.Int32(1)}}
	data := []byte("bytes")
	if operation == "empty-put" {
		data = nil
	}
	if !baseline {
		switch operation {
		case "create":
			_, err := fs.initiateMultipartUpload(ctx, "key", "")
			return err
		case "complete":
			return fs.completeMultipartUpload(ctx, "key", "upload-1", parts)
		default:
			return fs.handleUpload(ctx, bytes.NewReader(data), "key", "")
		}
	}
	switch operation {
	case "create":
		_, err := fs.svc.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String("bucket"), Key: aws.String("key")})
		return err
	case "complete":
		_, err := fs.svc.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket: aws.String("bucket"), Key: aws.String("key"), UploadId: aws.String("upload-1"),
			MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
		})
		return err
	default:
		_, err := fs.svc.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("bucket"), Key: aws.String("key"), Body: bytes.NewReader(data)})
		return err
	}
}

func TestS3UploadSingleAttempt(t *testing.T) {
	for _, operation := range []string{"put", "empty-put", "create", "complete"} {
		for _, fault := range []string{"success", "503", "drop"} {
			for _, baseline := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/baseline=%t", operation, fault, baseline), func(t *testing.T) {
					var attempts atomic.Int32
					fs := retryTestFS(t, func(w http.ResponseWriter, r *http.Request) {
						if _, err := io.Copy(io.Discard, r.Body); err != nil {
							t.Error(err)
						}
						if attempts.Add(1) == 1 && fault != "success" {
							retryTestFault(t, w, fault)
							return
						}
						retryTestSuccess(w, operation)
					})
					err := retryTestInvoke(t.Context(), fs, operation, baseline)
					wantError := !baseline && fault != "success"
					if (err != nil) != wantError {
						t.Fatalf("error = %v, want error %t", err, wantError)
					}
					wantAttempts := int32(1)
					if baseline && fault != "success" {
						wantAttempts = 2
					}
					if attempts.Load() != wantAttempts {
						t.Fatalf("HTTP requests = %d, want %d", attempts.Load(), wantAttempts)
					}
				})
			}
		}
	}
}

func TestS3CompleteEmbeddedErrorSingleAttempt(t *testing.T) {
	for _, baseline := range []bool{false, true} {
		t.Run(fmt.Sprintf("baseline=%t", baseline), func(t *testing.T) {
			var attempts atomic.Int32
			fs := retryTestFS(t, func(w http.ResponseWriter, r *http.Request) {
				if attempts.Add(1) == 1 {
					retryTestFault(t, w, "embedded")
					return
				}
				retryTestSuccess(w, "complete")
			})
			err := retryTestInvoke(t.Context(), fs, "complete", baseline)
			if baseline {
				if err != nil || attempts.Load() != 2 {
					t.Fatalf("baseline error = %v, requests = %d", err, attempts.Load())
				}
				return
			}
			var apiError smithy.APIError
			if !errors.As(err, &apiError) || apiError.ErrorCode() != "InternalError" || attempts.Load() != 1 {
				t.Fatalf("error = %v, requests = %d; want one embedded InternalError", err, attempts.Load())
			}
		})
	}
}

func TestS3CompleteCancellationAfterHeaders(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var attempts atomic.Int32
	fs := retryTestFS(t, func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			close(started)
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- retryTestInvoke(ctx, fs, "complete", false) }()
	select {
	case <-started:
		cancel()
	case <-time.After(5 * time.Second):
		t.Fatal("completion did not reach response headers")
	}
	select {
	case err := <-done:
		if err == nil || attempts.Load() != 1 {
			t.Fatalf("cancellation error = %v, requests = %d", err, attempts.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled completion did not return")
	}
}

func TestS3UploadPartRetainsRetry(t *testing.T) {
	for _, fault := range []string{"drop", "503", "exhausted"} {
		t.Run(fault, func(t *testing.T) {
			var attempts atomic.Int32
			fs := retryTestFS(t, func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != "part bytes" || r.Method != "PUT" || r.URL.Path != "/bucket/key" ||
					r.URL.Query().Get("uploadId") != "upload-1" || r.URL.Query().Get("partNumber") != "7" {
					t.Errorf("part identity/body changed: %s %s, body=%q, error=%v", r.Method, r.URL, body, err)
				}
				if attempts.Add(1) == 1 || fault == "exhausted" {
					retryTestFault(t, w, fault)
					return
				}
				retryTestSuccess(w, "part")
			})
			etag, err := fs.uploadPart(t.Context(), "key", "upload-1", 7, []byte("part bytes"))
			if fault == "exhausted" {
				if err == nil || attempts.Load() != 3 {
					t.Fatalf("error=%v requests=%d, want error after three attempts", err, attempts.Load())
				}
			} else if err != nil || aws.ToString(etag) != `"fixture"` || attempts.Load() != 2 {
				t.Fatalf("etag=%v error=%v requests=%d", etag, err, attempts.Load())
			}
		})
	}
}

func TestS3UploadMultipartDispatch(t *testing.T) {
	for _, failPart := range []bool{false, true} {
		t.Run(fmt.Sprintf("failPart=%t", failPart), func(t *testing.T) {
			var mu sync.Mutex
			counts := make(map[string]int)
			parts := make(map[string]string)
			fs := retryTestFS(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				operation := "complete"
				switch {
				case r.URL.Query().Has("uploads"):
					operation = "create"
				case r.Method == "DELETE":
					operation = "abort"
				case r.Method == "PUT":
					operation = "part"
				}
				counts[operation]++
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if operation != "create" && r.URL.Query().Get("uploadId") != "upload-1" {
					t.Errorf("wrong upload ID: %s", r.URL)
				}
				if operation == "part" {
					parts[r.URL.Query().Get("partNumber")] = string(body)
					if failPart {
						retryTestFault(t, w, "503")
						return
					}
				}
				if operation == "complete" && (!strings.Contains(string(body), "<PartNumber>1</PartNumber>") || !strings.Contains(string(body), "<PartNumber>2</PartNumber>")) {
					t.Errorf("completion did not contain both parts: %s", body)
				}
				retryTestSuccess(w, operation)
			})
			err := fs.handleUpload(t.Context(), strings.NewReader("12345678tail"), "key", "")
			mu.Lock()
			defer mu.Unlock()
			if counts["create"] != 1 {
				t.Fatalf("initiation count = %d", counts["create"])
			}
			if failPart {
				if err == nil || counts["abort"] != 1 || counts["complete"] != 0 || counts["part"] != 3 {
					t.Fatalf("error=%v operation counts=%v", err, counts)
				}
			} else if err != nil || counts["abort"] != 0 || counts["complete"] != 1 || counts["part"] != 2 || parts["1"] != "12345678" || parts["2"] != "tail" {
				t.Fatalf("error=%v operation counts=%v parts=%v", err, counts, parts)
			}
		})
	}
}

func TestS3ReadRetriesUnaffected(t *testing.T) {
	var mu sync.Mutex
	counts := make(map[string]int)
	fs := retryTestFS(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		operation := r.Method
		if r.URL.Query().Has("list-type") {
			operation = "LIST"
		}
		counts[operation]++
		if counts[operation] == 1 {
			retryTestFault(t, w, "503")
			return
		}
		switch operation {
		case "HEAD":
			w.Header().Set("Content-Length", "5")
		case "GET":
			fmt.Fprint(w, "bytes")
		case "LIST":
			fmt.Fprint(w, `<ListBucketResult><Name>bucket</Name><IsTruncated>false</IsTruncated></ListBucketResult>`)
		default:
			retryTestSuccess(w, "put")
		}
	})
	if err := fs.singlePartUpload(t.Context(), "key", "", []byte("bytes")); err == nil {
		t.Fatal("upload should fail after the first response")
	}
	if _, err := fs.headObject("key"); err != nil {
		t.Fatal(err)
	}
	object, err := fs.svc.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String("bucket"), Key: aws.String("key")})
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(object.Body)
	closeErr := object.Body.Close()
	if readErr != nil || closeErr != nil || string(body) != "bytes" {
		t.Fatalf("body=%q read=%v close=%v", body, readErr, closeErr)
	}
	if _, err := fs.svc.ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: aws.String("bucket")}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if counts["PUT"] != 1 || counts["HEAD"] != 2 || counts["GET"] != 2 || counts["LIST"] != 2 {
		t.Fatalf("operation requests = %v", counts)
	}
}

func TestS3CredentialRetriesUnaffected(t *testing.T) {
	var credentialsCalls, putCalls atomic.Int32
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if credentialsCalls.Add(1) == 1 {
			retryTestFault(t, w, "503")
			return
		}
		fmt.Fprint(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>fixture-role</AccessKeyId><SecretAccessKey>fixture-secret</SecretAccessKey><SessionToken>fixture-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/fixture/session</Arn><AssumedRoleId>fixture:session</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	defer stsServer.Close()
	fs := retryTestFS(t, func(w http.ResponseWriter, r *http.Request) {
		putCalls.Add(1)
		if !strings.Contains(r.Header.Get("Authorization"), "Credential=fixture-role/") {
			t.Error("upload did not use the assumed role credentials")
		}
		retryTestSuccess(w, "put")
	})
	stsClient := sts.NewFromConfig(retryTestConfig(), func(o *sts.Options) { o.BaseEndpoint = aws.String(stsServer.URL) })
	opts := fs.svc.Options()
	opts.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsClient, "arn:aws:iam::123456789012:role/fixture"))
	fs.svc = s3.New(opts)
	if err := fs.singlePartUpload(t.Context(), "key", "", []byte("bytes")); err != nil {
		t.Fatal(err)
	}
	if credentialsCalls.Load() != 2 || putCalls.Load() != 1 {
		t.Fatalf("STS requests=%d, PUT requests=%d", credentialsCalls.Load(), putCalls.Load())
	}
}
