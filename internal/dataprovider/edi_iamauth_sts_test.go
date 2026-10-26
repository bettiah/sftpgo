// Copyright (C) 2026 EDI Platform contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build edi

// Run file-scoped via edi/test.sh only; package-mode -tags edi contaminates globals.
package dataprovider

import (
	"context"
	"database/sql"
	"encoding/pem"
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
// the connection and the request and never answers.
type ediFakeSTS struct {
	srv      *httptest.Server
	stall    atomic.Bool
	requests atomic.Int64
	keyID    string
	release  chan struct{}
}

func (f *ediFakeSTS) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		// Reading the body lets net/http cancel the request context when the client hangs up.
		_, _ = io.Copy(io.Discard, r.Body)
		if f.stall.Load() {
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
		f.srv.Close()
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
		name         string
		tokenTimeout time.Duration
	}{
		// The refresh budget ends first (production ordering): the refresh itself times out.
		{"refresh budget first", 2 * time.Second},
		// The hook deadline ends first: the caller stops waiting while the refresh continues.
		{"hook deadline first", 100 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logPath := ediIAMSetup(t)
			pg := ediStartFakePG(t)
			sts := ediStartFakeSTS(t, nil)
			ediWebIdentityEnv(t, sts.srv.URL, ediSTSCertPEM(sts))
			iamTokenTimeout = tc.tokenTimeout
			db, a := ediIAMHandle(t, pg)

			sts.stall.Store(true)
			start := time.Now()
			if err := db.PingContext(context.Background()); err == nil {
				t.Fatal("connect succeeded against a stalled STS")
			}
			// Bounded by the hook deadline and by the request budget, never by the stall.
			if elapsed := time.Since(start); elapsed > tc.tokenTimeout+500*time.Millisecond {
				t.Fatalf("the hook waited %v", elapsed)
			}
			if sts.requests.Load() == 0 {
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
