// Copyright (C) 2026 EDI Platform contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build edi

// Run file-scoped via edi/test.sh only; package-mode -tags edi contaminates globals.
package dataprovider

import (
	"context"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ediFakeSTS is a local TLS endpoint for AssumeRoleWithWebIdentity. In stall mode it accepts
// the connection and the request and never answers; in body-stall mode it sends the response
// headers and then never sends the body.
type ediFakeSTS struct {
	srv       *httptest.Server
	stall     atomic.Bool
	bodyStall atomic.Bool
	requests  atomic.Int64
	keyID     string
	release   chan struct{}
}

func (f *ediFakeSTS) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		// Reading the body lets net/http cancel the request context when the client hangs up.
		_, _ = io.Copy(io.Discard, r.Body)
		if f.bodyStall.Load() {
			w.Header().Set("Content-Type", "text/xml")
			w.WriteHeader(http.StatusOK)
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
		}
		if f.stall.Load() || f.bodyStall.Load() {
			select {
			case <-r.Context().Done():
			case <-f.release:
			}
			// Abort rather than answer: an empty 200 makes the SDK's web identity provider
			// dereference nil credentials and crash the process.
			panic(http.ErrAbortHandler)
		}
		w.Header().Set("Content-Type", "text/xml")
		// Short-lived credentials, so that every connect a second later refreshes again.
		fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
<AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>fixture-sts-secret</SecretAccessKey>
<SessionToken>fixture-sts-session</SessionToken><Expiration>%s</Expiration></Credentials>
<AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/fixture/s</Arn><AssumedRoleId>AROAFIXTURE:s</AssumedRoleId></AssumedRoleUser>
</AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>fixture</RequestId></ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>`, f.keyID, time.Now().Add(time.Second).UTC().Format(time.RFC3339))
	})
}

// ediStartFakeSTS serves TLS on a new port, or plain HTTP on ln when it is given.
func ediStartFakeSTS(t *testing.T, ln net.Listener) *ediFakeSTS {
	t.Helper()
	f := &ediFakeSTS{keyID: "ASIAEDISTSFIXTURE", release: make(chan struct{})}
	f.srv = httptest.NewUnstartedServer(f.handler())
	if ln != nil {
		f.srv.Listener = ln
		f.srv.Start()
	} else {
		f.srv.StartTLS()
	}
	t.Cleanup(func() {
		close(f.release)
		f.srv.CloseClientConnections()
		done := make(chan struct{})
		go func() {
			f.srv.Close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the fake STS did not shut down")
		}
	})
	return f
}

// ediWebIdentityEnv points the production SDK loader at endpoint through the IRSA variables.
func ediWebIdentityEnv(t *testing.T, endpoint string, caPEM []byte) {
	t.Helper()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("fixture-web-identity-token"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_REGION", "eu-west-1")
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/fixture")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenFile)
	t.Setenv("AWS_ENDPOINT_URL_STS", endpoint)
	if caPEM != nil {
		caFile := filepath.Join(dir, "ca.pem")
		if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AWS_CA_BUNDLE", caFile)
	}
	iamSTSConnectTimeout = 200 * time.Millisecond
	iamSTSResponseTimeout = 250 * time.Millisecond
	iamSTSRequestTimeout = 300 * time.Millisecond
	iamSTSMaxBackoff = 50 * time.Millisecond
}

// ediIAMHandle opens the IAM pool with the production credential chain and no idle
// connections, so each ping is exactly one physical connect.
func ediIAMHandle(t *testing.T, pg *ediFakePG) (*sql.DB, *pgsqlIAMAuth) {
	t.Helper()
	config = ediIAMConfig(pg)
	cfg, err := parsePGSQLIAMConfig()
	if err != nil {
		t.Fatal(err)
	}
	a, err := newPGSQLIAMAuth(cfg)
	if err != nil {
		t.Fatal(err)
	}
	db := openPGSQLIAMHandle(cfg, a)
	setPGSQLPoolLimits(db)
	db.SetMaxIdleConns(0)
	t.Cleanup(func() { _ = db.Close() })
	return db, a
}

func ediSTSCertPEM(f *ediFakeSTS) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
}

func ediPingUntilOK(t *testing.T, db *sql.DB) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := db.PingContext(context.Background())
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no recovery: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

const ediBuildFailed = "iam auth: token build failed"

// A stalled STS response: the connect fails within the hook deadline with the failure line,
// the shared refresh ends within its budget, and connects recover without a restart.
func TestEDIIAMStalledSTSRecovers(t *testing.T) {
	for _, tc := range []struct {
		name          string
		tokenTimeout  time.Duration
		countAttempts bool
	}{
		// The refresh budget ends first (production ordering): the refresh itself times out.
		{"refresh budget first", 2 * time.Second, true},
		// The hook deadline ends first: the caller stops waiting while the refresh continues.
		{"hook deadline first", 100 * time.Millisecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logPath := ediIAMSetup(t)
			pg := ediStartFakePG(t)
			sts := ediStartFakeSTS(t, nil)
			ediWebIdentityEnv(t, sts.srv.URL, ediSTSCertPEM(sts))
			iamTokenTimeout = tc.tokenTimeout
			if !tc.countAttempts {
				// A refresh that outlasts the hook deadline, so only that deadline can end the wait.
				iamSTSResponseTimeout, iamSTSRequestTimeout = time.Second, time.Second
			}
			db, a := ediIAMHandle(t, pg)

			sts.stall.Store(true)
			start := time.Now()
			if err := db.PingContext(context.Background()); err == nil {
				t.Fatal("connect succeeded against a stalled STS")
			}
			// Bounded by the hook deadline and by the request budget, never by the stall.
			if elapsed := time.Since(start); elapsed > tc.tokenTimeout+300*time.Millisecond {
				t.Fatalf("the hook waited %v", elapsed)
			}
			if tc.countAttempts {
				// The refresh ended before the caller gave up: exactly the attempt budget.
				time.Sleep(300 * time.Millisecond)
				if got := sts.requests.Load(); got != int64(iamSTSMaxAttempts) {
					t.Fatalf("%d STS attempts, want %d", got, iamSTSMaxAttempts)
				}
			} else if sts.requests.Load() == 0 {
				t.Fatal("the stalled endpoint saw no request")
			}
			log := ediReadLog(t, logPath)
			if !strings.Contains(log, ediBuildFailed+", class: timeout") {
				t.Fatalf("no timeout-class build failure line")
			}
			if n := strings.Count(log, ediBuildFailed); int64(n) != a.buildFailures.Load() || n == 0 {
				t.Fatalf("%d failure lines for %d build failures", n, a.buildFailures.Load())
			}
			if pwds, _ := pg.passwords(); len(pwds) != 0 {
				t.Fatal("a connect reached the database without a token")
			}

			sts.stall.Store(false)
			ediPingUntilOK(t, db)
			pwds, _ := pg.passwords()
			if len(pwds) == 0 || !strings.Contains(pwds[len(pwds)-1], "X-Amz-Credential="+sts.keyID+"%2F") {
				t.Fatal("the recovered connect does not use the refreshed credentials")
			}
			failures := a.buildFailures.Load()
			// Later connects refresh the one-second credentials and stay quiet.
			time.Sleep(1100 * time.Millisecond)
			for range 3 {
				if err := db.PingContext(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			log = ediReadLog(t, logPath)
			if n := strings.Count(log, "iam auth credentials: expiry changed"); n < 2 {
				t.Fatalf("%d credential snapshots across refreshed one-second credentials", n)
			}
			if a.buildFailures.Load() != failures || int64(strings.Count(log, ediBuildFailed)) != failures ||
				!strings.Contains(log, "iam auth recovered: token build succeeded") {
				t.Fatal("the failure signal did not stop after recovery")
			}
			for _, secret := range append([]string{"fixture-sts-secret", "fixture-web-identity-token"}, pwds...) {
				if strings.Contains(log, secret) {
					t.Fatal("a secret, the web identity token or an auth token reached the log")
				}
			}
		})
	}
}

// Connection refused at the STS endpoint: a prompt failure with the failure line, then
// recovery once an endpoint answers there.
func TestEDIIAMRefusedSTSRecovers(t *testing.T) {
	logPath := ediIAMSetup(t)
	pg := ediStartFakePG(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	ediWebIdentityEnv(t, "http://"+addr, nil)
	db, a := ediIAMHandle(t, pg)
	for range 2 {
		start := time.Now()
		if err := db.PingContext(context.Background()); err == nil {
			t.Fatal("connect succeeded with STS refusing connections")
		}
		if time.Since(start) > 3*time.Second {
			t.Fatal("refusal was not prompt")
		}
	}
	log := ediReadLog(t, logPath)
	if n := strings.Count(log, ediBuildFailed+", class: credentials"); n != 2 || a.buildFailures.Load() != 2 {
		t.Fatalf("%d credentials-class failure lines for %d failures", n, a.buildFailures.Load())
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("rebinding the refused port: %v", err)
	}
	ediStartFakeSTS(t, listener)
	ediPingUntilOK(t, db)
	if !strings.Contains(ediReadLog(t, logPath), "iam auth recovered: token build succeeded") {
		t.Fatal("no recovery line")
	}
}

// The caller cancels while the refresh stalls: the connect returns promptly with the failure
// line, although the hook deadline is long.
func TestEDIIAMCallerCancellation(t *testing.T) {
	logPath := ediIAMSetup(t)
	pg := ediStartFakePG(t)
	sts := ediStartFakeSTS(t, nil)
	ediWebIdentityEnv(t, sts.srv.URL, ediSTSCertPEM(sts))
	iamSTSRequestTimeout = 5 * time.Second
	iamSTSResponseTimeout = 5 * time.Second
	db, _ := ediIAMHandle(t, pg)
	sts.stall.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	if err := db.PingContext(ctx); err == nil {
		t.Fatal("connect succeeded against a stalled STS")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancellation took %v", elapsed)
	}
	if !strings.Contains(ediReadLog(t, logPath), ediBuildFailed+", class: canceled") {
		t.Fatal("no canceled-class build failure line")
	}
}

// Headers arrive and the body never does: only the overall request timeout ends the attempt
// (the response-header timeout has nothing to wait for), within the attempt budget.
func TestEDIIAMBodyStalledSTSIsBounded(t *testing.T) {
	logPath := ediIAMSetup(t)
	pg := ediStartFakePG(t)
	sts := ediStartFakeSTS(t, nil)
	ediWebIdentityEnv(t, sts.srv.URL, ediSTSCertPEM(sts))
	iamSTSResponseTimeout = 10 * time.Second
	iamTokenTimeout = 6 * time.Second
	db, _ := ediIAMHandle(t, pg)
	sts.bodyStall.Store(true)
	start := time.Now()
	if err := db.PingContext(context.Background()); err == nil {
		t.Fatal("connect succeeded against a body-stalled STS")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("the refresh ran %v: the request timeout did not end it", elapsed)
	}
	time.Sleep(300 * time.Millisecond)
	if got := sts.requests.Load(); got < 1 || got > int64(iamSTSMaxAttempts) {
		t.Fatalf("%d STS attempts, want 1..%d", got, iamSTSMaxAttempts)
	}
	if !strings.Contains(ediReadLog(t, logPath), ediBuildFailed+", class: ") {
		t.Fatal("no build failure line")
	}
	sts.bodyStall.Store(false)
	ediPingUntilOK(t, db)
}

// Concurrent connects share one refresh through the cache: one waiter cancels, the others
// recover through that same refresh once STS answers, and a later refresh also succeeds.
func TestEDIIAMConcurrentWaitersShareRefresh(t *testing.T) {
	logPath := ediIAMSetup(t)
	pg := ediStartFakePG(t)
	sts := ediStartFakeSTS(t, nil)
	ediWebIdentityEnv(t, sts.srv.URL, ediSTSCertPEM(sts))
	iamTokenTimeout = 6 * time.Second
	db, a := ediIAMHandle(t, pg)
	db.SetMaxOpenConns(4)
	sts.stall.Store(true)

	type result struct {
		err     error
		elapsed time.Duration
	}
	results := make([]chan result, 4)
	for i := range results {
		results[i] = make(chan result, 1)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		if i == 0 {
			time.AfterFunc(50*time.Millisecond, cancel)
		}
		go func() {
			start := time.Now()
			err := db.PingContext(ctx)
			results[i] <- result{err, time.Since(start)}
		}()
	}
	// The first attempt is stalled; let STS answer the retry.
	time.Sleep(100 * time.Millisecond)
	sts.stall.Store(false)
	for i, ch := range results {
		r := <-ch
		if i == 0 {
			if r.err == nil || r.elapsed > time.Second {
				t.Fatalf("the canceled waiter: err=%v after %v", r.err, r.elapsed)
			}
			continue
		}
		if r.err != nil {
			t.Fatalf("waiter %d: %v", i, r.err)
		}
	}
	if got := sts.requests.Load(); got != 2 {
		t.Fatalf("%d STS requests: the waiters did not share one refresh (stalled attempt plus retry)", got)
	}
	log := ediReadLog(t, logPath)
	if !strings.Contains(log, ediBuildFailed+", class: canceled") || a.buildFailures.Load() != 1 {
		t.Fatalf("want exactly the canceled waiter's failure line, failures %d", a.buildFailures.Load())
	}
	// The same auth object refreshes again once the one-second credentials expire.
	time.Sleep(1100 * time.Millisecond)
	before := sts.requests.Load()
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sts.requests.Load() != before+1 {
		t.Fatal("no fresh refresh after expiry")
	}
}

// The loader's retryer carries the attempt limit and the backoff cap, so a refresh budget is
// attempts × request timeout plus at most one capped backoff.
func TestEDIIAMRetryBudget(t *testing.T) {
	ediIAMSetup(t)
	t.Setenv("AWS_REGION", "eu-west-1")
	iamSTSMaxBackoff = 50 * time.Millisecond
	cfg, err := iamLoadAWSConfig(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Retryer()
	if r.MaxAttempts() != iamSTSMaxAttempts {
		t.Fatalf("max attempts %d, want %d", r.MaxAttempts(), iamSTSMaxAttempts)
	}
	for range 50 {
		d, err := r.RetryDelay(1, errors.New("fixture"))
		if err != nil {
			t.Fatal(err)
		}
		if d > iamSTSMaxBackoff {
			t.Fatalf("retry backoff %v exceeds the %v cap", d, iamSTSMaxBackoff)
		}
	}
}
