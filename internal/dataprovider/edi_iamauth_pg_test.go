// Copyright (C) 2026 EDI Platform contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build edi

// Run file-scoped via edi/test.sh only, with SFTPGO_EDI_PG_ADMIN_URL naming a local
// PostgreSQL superuser connection; it fails rather than skips without one.
package dataprovider

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/jackc/pgx/v5"
)

// A real PostgreSQL backend: one hook call, one token build and one backend PID per physical
// connect across the shortened recycle, and the failure signal when the stub signer fails.
// Local PostgreSQL has no TLS, so this opens the IAM pool on a parsed sslmode=disable config;
// the verify-full refusal and the real signer are covered with the TLS fake server. The local
// server trusts loopback logins, so this proves the hook and connect accounting, not that
// PostgreSQL checked the password; the fake server and Sitting B prove that.
func TestEDIIAMLocalPostgres(t *testing.T) {
	adminURL := os.Getenv("SFTPGO_EDI_PG_ADMIN_URL")
	if adminURL == "" {
		t.Fatal("SFTPGO_EDI_PG_ADMIN_URL is required")
	}
	logPath := ediIAMSetup(t)
	admin, err := pgx.Connect(context.Background(), adminURL)
	if err != nil {
		t.Fatal(err)
	}
	name := "edi_iam_" + ediRandomHex(t)
	password := "throwaway-" + ediRandomHex(t)
	exec := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(context.Background(), sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE ROLE "` + name + `" LOGIN PASSWORD '` + password + `'`)
	// Registered before the pool's cleanup, so it runs after the pool is closed. The admin
	// connection closes only here, and a failed drop fails the test.
	t.Cleanup(func() {
		ctx := context.Background()
		defer admin.Close(ctx)
		for _, sql := range []string{`DROP DATABASE IF EXISTS "` + name + `" WITH (FORCE)`, `DROP ROLE IF EXISTS "` + name + `"`} {
			if _, err := admin.Exec(ctx, sql); err != nil {
				t.Errorf("cleanup %q: %v", sql, err)
			}
		}
	})
	exec(`CREATE DATABASE "` + name + `" OWNER "` + name + `"`)

	cc := admin.Config()
	cfg, err := pgx.ParseConfig("host=" + cc.Host + " port=" + strconv.Itoa(int(cc.Port)) + " dbname=" + name + " user=" + name + " sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	var signerFails atomic.Bool
	var endpoints atomic.Value
	iamLoadAWSConfig = ediFakeAWS(&ediFakeCreds{secret: "fixture-secret", expires: time.Now().Add(time.Hour)}, "eu-west-1")
	iamBuildToken = func(_ context.Context, endpoint, _, user string, _ aws.CredentialsProvider) (string, error) {
		if signerFails.Load() {
			return "", errors.New("fixture: signer failed")
		}
		endpoints.Store(endpoint + "/" + user)
		return password, nil
	}
	a, err := newPGSQLIAMAuth(cfg)
	if err != nil {
		t.Fatal(err)
	}
	config.PoolSize = 1
	pgsqlConnMaxLifetime = 300 * time.Millisecond
	db := openPGSQLIAMHandle(cfg, a)
	t.Cleanup(func() { _ = db.Close() })
	setPGSQLPoolLimits(db)

	pids := map[int]bool{}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var pid int
		if err := db.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
			t.Fatal(err)
		}
		pids[pid] = true
		time.Sleep(20 * time.Millisecond)
	}
	if len(pids) < 4 {
		t.Fatalf("only %d backends across the shortened recycle", len(pids))
	}
	if a.connectAttempts.Load() != int64(len(pids)) || a.builds.Load() != int64(len(pids)) || a.connects.Load() != int64(len(pids)) {
		t.Fatalf("%d backends, %s", len(pids), a.counters())
	}
	if got := endpoints.Load(); got != cc.Host+":"+strconv.Itoa(int(cc.Port))+"/"+name {
		t.Fatalf("token endpoint %v", got)
	}

	// The signer fails: new connects fail with one build-failure line each, then stop.
	signerFails.Store(true)
	time.Sleep(400 * time.Millisecond)
	for range 3 {
		if err := db.PingContext(context.Background()); err == nil {
			t.Fatal("ping succeeded with a failing signer")
		}
	}
	log := ediReadLog(t, logPath)
	if n := strings.Count(log, "iam auth: token build failed, class: signer"); n != 3 {
		t.Fatalf("%d build-failure lines for 3 failed connects", n)
	}
	signerFails.Store(false)
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	log = ediReadLog(t, logPath)
	if strings.Count(log, "iam auth: token build failed") != 3 || !strings.Contains(log, "iam auth recovered") {
		t.Fatal("the signal did not stop after recovery")
	}
	if strings.Contains(log, password) {
		t.Fatal("the password reached the log")
	}
}
