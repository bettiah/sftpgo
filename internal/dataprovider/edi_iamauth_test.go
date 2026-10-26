// Copyright (C) 2026 EDI Platform contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build edi

// Run file-scoped via edi/test.sh only; package-mode -tags edi contaminates globals.
package dataprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/rs/zerolog"

	"github.com/drakkan/sftpgo/v2/internal/logger"
)

const ediIAMAccessKey = "AKIDEDIIAMTEST"

// ediFakeCreds is a credentials provider that never leaves the process.
type ediFakeCreds struct {
	secret  string
	expires time.Time
	fail    atomic.Bool
	calls   atomic.Int64
}

func (c *ediFakeCreds) Retrieve(context.Context) (aws.Credentials, error) {
	c.calls.Add(1)
	if c.fail.Load() {
		return aws.Credentials{}, errors.New("fixture: credentials unavailable")
	}
	return aws.Credentials{AccessKeyID: ediIAMAccessKey, SecretAccessKey: c.secret, SessionToken: "fixture-session-" + c.secret,
		Source: "fixture", CanExpire: true, Expires: c.expires}, nil
}

func ediRandomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// ediFakePG speaks just enough of the PostgreSQL protocol over TLS to authenticate with a
// cleartext password, record it, and answer pings.
type ediFakePG struct {
	ln       net.Listener
	tlsCfg   *tls.Config
	caPath   string
	port     int
	refuse   atomic.Bool
	mu       sync.Mutex
	pwds     []string
	users    []string
	conns    []net.Conn
	accepted atomic.Int64
	wg       sync.WaitGroup
}

func ediStartFakePG(t *testing.T) *ediFakePG {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &ediFakePG{
		ln:     ln,
		caPath: caPath,
		port:   ln.Addr().(*net.TCPAddr).Port,
		tlsCfg: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12},
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepted.Add(1)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handle(c)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		s.dropConnections()
		s.wg.Wait()
	})
	return s
}

func (s *ediFakePG) handle(raw net.Conn) {
	defer raw.Close()
	be := pgproto3.NewBackend(raw, raw)
	msg, err := be.ReceiveStartupMessage()
	if err != nil {
		return
	}
	if _, ok := msg.(*pgproto3.SSLRequest); !ok {
		return
	}
	if _, err := raw.Write([]byte("S")); err != nil {
		return
	}
	conn := tls.Server(raw, s.tlsCfg)
	defer conn.Close()
	s.mu.Lock()
	s.conns = append(s.conns, conn)
	s.mu.Unlock()
	be = pgproto3.NewBackend(conn, conn)
	msg, err = be.ReceiveStartupMessage()
	if err != nil {
		return
	}
	startup, ok := msg.(*pgproto3.StartupMessage)
	if !ok {
		return
	}
	be.Send(&pgproto3.AuthenticationCleartextPassword{})
	if be.Flush() != nil || be.SetAuthType(pgproto3.AuthTypeCleartextPassword) != nil {
		return
	}
	msg, err = be.Receive()
	if err != nil {
		return
	}
	pw, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		return
	}
	s.mu.Lock()
	s.pwds = append(s.pwds, pw.Password)
	s.users = append(s.users, startup.Parameters["user"])
	s.mu.Unlock()
	if s.refuse.Load() {
		be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"})
		_ = be.Flush()
		return
	}
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "18.0"})
	be.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})
	be.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	be.Send(&pgproto3.BackendKeyData{ProcessID: uint32(s.accepted.Load()), SecretKey: []byte{1, 2, 3, 4}})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if be.Flush() != nil {
		return
	}
	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		if _, ok := msg.(*pgproto3.Query); !ok {
			return
		}
		be.Send(&pgproto3.EmptyQueryResponse{})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		if be.Flush() != nil {
			return
		}
	}
}

// dropConnections closes every authenticated connection, as a server restart would.
func (s *ediFakePG) dropConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
}

func (s *ediFakePG) passwords() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.pwds...), append([]string(nil), s.users...)
}

// ediIAMSetup isolates the process environment, the provider globals and the log, and
// returns the log file path. It never touches the real home directory or ~/.aws.
func ediIAMSetup(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, name := range append([]string{"PGHOST", "PGPORT", "PGUSER", "PGDATABASE", "PGSSLMODE", "PGSSLROOTCERT",
		"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
		// The STS refresh budget and attempt counts are qualified in the SDK's default retry mode.
		"AWS_NEW_RETRIES_2026"},
		pgsqlIAMRefusedEnv...) {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "no-aws-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "no-aws-credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	prevConfig, prevProvider := config, provider
	prevLifetime, prevIdle := pgsqlConnMaxLifetime, pgsqlConnMaxIdleTime
	prevLoad, prevBuild := iamLoadAWSConfig, iamBuildToken
	prevToken, prevSTS := iamTokenTimeout, [3]time.Duration{iamSTSConnectTimeout, iamSTSResponseTimeout, iamSTSRequestTimeout}
	prevAttempts, prevBackoff := iamSTSMaxAttempts, iamSTSMaxBackoff
	t.Cleanup(func() {
		iamTokenTimeout = prevToken
		iamSTSMaxAttempts, iamSTSMaxBackoff = prevAttempts, prevBackoff
		iamSTSConnectTimeout, iamSTSResponseTimeout, iamSTSRequestTimeout = prevSTS[0], prevSTS[1], prevSTS[2]
		if p, ok := provider.(*PGSQLProvider); ok && p != prevProvider {
			_ = p.close()
		}
		config, provider = prevConfig, prevProvider
		pgsqlConnMaxLifetime, pgsqlConnMaxIdleTime = prevLifetime, prevIdle
		iamLoadAWSConfig, iamBuildToken = prevLoad, prevBuild
		logger.DisableLogger()
	})
	logPath := filepath.Join(t.TempDir(), "sftpgo.log")
	logger.InitLogger(logPath, 10, 1, 1, false, true, zerolog.DebugLevel)
	logSender = "dataprovider_postgresql"
	return logPath
}

func ediFakeAWS(creds *ediFakeCreds, region string) func(context.Context, string) (aws.Config, error) {
	return func(_ context.Context, override string) (aws.Config, error) {
		if override != "" {
			region = override
		}
		return aws.Config{Region: region, Credentials: aws.NewCredentialsCache(creds)}, nil
	}
}

func ediIAMConfig(s *ediFakePG) Config {
	return Config{Driver: PGSQLDataProviderName, Host: "localhost", Port: s.port, Name: "edi", Username: "sftpgo_app",
		SSLMode: 3, RootCert: s.caPath, AWSIAMAuth: true, PoolSize: 1}
}

func ediReadLog(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return string(b)
}

func ediEventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestEDIIAMRefusals(t *testing.T) {
	s := ediStartFakePG(t)
	pgpassLine := "*:*:*:*:pgpass-" + "fixture\n"
	serviceFile := "[edi]\nhost=localhost\npassword=service-fixture\n"
	cases := []struct {
		name    string
		mutate  func(t *testing.T, c *Config)
		want    string
		secrets []string
	}{
		{"config password", func(_ *testing.T, c *Config) { c.Password = "x" }, "data_provider.password is set", nil},
		{"PGPASSWORD", func(t *testing.T, _ *Config) { t.Setenv("PGPASSWORD", "x") }, "PGPASSWORD is set", nil},
		{"PGPASSWORD empty", func(t *testing.T, _ *Config) { t.Setenv("PGPASSWORD", "") }, "PGPASSWORD is set", nil},
		{"PGPASSFILE", func(t *testing.T, _ *Config) { t.Setenv("PGPASSFILE", "/nonexistent") }, "PGPASSFILE is set", nil},
		{"PGSERVICE", func(t *testing.T, _ *Config) { t.Setenv("PGSERVICE", "edi") }, "PGSERVICE is set", nil},
		{"PGSERVICEFILE", func(t *testing.T, _ *Config) { t.Setenv("PGSERVICEFILE", "/nonexistent") }, "PGSERVICEFILE is set", nil},
		{"default pgpass", func(t *testing.T, _ *Config) {
			if err := os.WriteFile(filepath.Join(os.Getenv("HOME"), ".pgpass"), []byte(pgpassLine), 0600); err != nil {
				t.Fatal(err)
			}
		}, "effective configuration has a password", []string{"pgpass-fixture"}},
		{"two hosts", func(_ *testing.T, c *Config) { c.Host = "localhost,127.0.0.1" }, "more than one host", nil},
		{"sslmode require", func(_ *testing.T, c *Config) { c.SSLMode = 1; c.RootCert = "" }, "TLS is not verify-full", nil},
		{"sslmode verify-ca", func(_ *testing.T, c *Config) { c.SSLMode = 2 }, "TLS is not verify-full", nil},
		{"sslmode prefer", func(_ *testing.T, c *Config) { c.SSLMode = 4 }, "more than one host or a TLS fallback", nil},
		{"sslmode disable", func(_ *testing.T, c *Config) { c.SSLMode = 0 }, "TLS is not verify-full", nil},
		{"connection string password", func(_ *testing.T, c *Config) {
			c.ConnectionString = "host=localhost dbname=edi user=sftpgo_app sslmode=verify-full password=conn-fixture"
		}, `invalid connection settings (key "password" is not allowed)`, []string{"conn-fixture"}},
		{"connection string service", func(_ *testing.T, c *Config) {
			c.ConnectionString = "service=edi sslmode=verify-full"
		}, `invalid connection settings (key "service" is not allowed)`, nil},
		{"connection string passfile", func(_ *testing.T, c *Config) {
			c.ConnectionString = "host=localhost sslmode=verify-full passfile=/nonexistent"
		}, `invalid connection settings (key "passfile" is not allowed)`, nil},
		// Malformed strings: the parser quotes fragments, which may be parts of a password.
		{"malformed keyword string", func(_ *testing.T, c *Config) {
			c.ConnectionString = "host=localhost password=Zq9alpha Xk7bravo sslmode=verify-full"
		}, "invalid connection settings (malformed keyword/value syntax)", []string{"Zq9alpha", "Xk7bravo"}},
		{"unknown key text", func(_ *testing.T, c *Config) {
			c.ConnectionString = "Tj6foxtrot=1 host=localhost sslmode=verify-full"
		}, "invalid connection settings (a key outside the allow-list)", []string{"Tj6foxtrot", "tj6foxtrot"}},
		{"malformed URI", func(_ *testing.T, c *Config) {
			c.ConnectionString = "postgres://sftpgo_app:Wm3charlie%ZZ@localhost/edi?sslmode=verify-full"
		}, "invalid connection settings (malformed URI)", []string{"Wm3charlie"}},
		{"URI password in the port position", func(_ *testing.T, c *Config) {
			c.ConnectionString = "postgres://sftpgo_app:Pd4delta:Rf5echo@localhost/edi?sslmode=verify-full"
		}, "invalid connection settings (", []string{"Pd4delta", "Rf5echo"}},
		{"no region", func(_ *testing.T, _ *Config) {
			iamLoadAWSConfig = ediFakeAWS(&ediFakeCreds{secret: "x"}, "")
		}, "no AWS region", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logPath := ediIAMSetup(t)
			var builds atomic.Int64
			iamLoadAWSConfig = ediFakeAWS(&ediFakeCreds{secret: "x", expires: time.Now().Add(time.Hour)}, "eu-west-1")
			iamBuildToken = func(context.Context, string, string, string, aws.CredentialsProvider) (string, error) {
				builds.Add(1)
				return "fixture-token", nil
			}
			c := ediIAMConfig(s)
			tc.mutate(t, &c)
			config = c
			before := s.accepted.Load()
			err := initializePGSQLProvider()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want %q", err, tc.want)
			}
			if builds.Load() != 0 || s.accepted.Load() != before {
				t.Fatalf("refusal after a token build or connect: builds=%d", builds.Load())
			}
			for _, secret := range append([]string{"conn-fixture", "pgpass-fixture", "service-fixture"}, tc.secrets...) {
				if strings.Contains(err.Error(), secret) || strings.Contains(ediReadLog(t, logPath), secret) {
					t.Fatalf("refusal leaked %q", secret)
				}
			}
		})
	}
	// The parsed-config check, not only the environment refusal, catches a password from
	// a service file: parse with PGSERVICE as libpq would, then apply the check.
	t.Run("service file password", func(t *testing.T) {
		ediIAMSetup(t)
		path := filepath.Join(t.TempDir(), "pg_service.conf")
		if err := os.WriteFile(path, []byte(serviceFile), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PGSERVICEFILE", path)
		t.Setenv("PGSERVICE", "edi")
		cfg, err := pgx.ParseConfig("sslmode=verify-full")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Password != "service-fixture" {
			t.Fatal("fixture did not load the service file")
		}
		if err := checkPGSQLIAMConnConfig(cfg); err == nil || !strings.Contains(err.Error(), "has a password") {
			t.Fatalf("err=%v", err)
		}
	})
	// Control: the same settings without a password source parse and pass.
	t.Run("control", func(t *testing.T) {
		ediIAMSetup(t)
		config = ediIAMConfig(s)
		cfg, err := parsePGSQLIAMConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Host != "localhost" || int(cfg.Port) != s.port || cfg.User != "sftpgo_app" || cfg.Password != "" {
			t.Fatalf("parsed %s:%d %s", cfg.Host, cfg.Port, cfg.User)
		}
	})
}

func TestEDIIAMRegion(t *testing.T) {
	ediIAMSetup(t)
	// The production loader with an isolated environment: no network, no ~/.aws.
	t.Setenv("AWS_ACCESS_KEY_ID", ediIAMAccessKey)
	t.Setenv("AWS_SECRET_ACCESS_KEY", "fixture-secret")
	cfg := &pgx.ConnConfig{}
	cfg.Host, cfg.Port, cfg.User = "localhost", 5432, "sftpgo_app"
	if _, err := newPGSQLIAMAuth(cfg); err == nil || !strings.Contains(err.Error(), "no AWS region") {
		t.Fatalf("err=%v", err)
	}
	t.Setenv("AWS_REGION", "eu-west-1")
	a, err := newPGSQLIAMAuth(cfg)
	if err != nil || a.region != "eu-west-1" {
		t.Fatalf("region=%v err=%v", a, err)
	}
	if _, ok := a.creds.(*aws.CredentialsCache); !ok {
		t.Fatal("credentials are not cached")
	}
	config.AWSIAMRegion = "eu-central-1"
	if a, err = newPGSQLIAMAuth(cfg); err != nil || a.region != "eu-central-1" {
		t.Fatalf("override: %v", err)
	}
}

func TestEDIIAMConnectionString(t *testing.T) {
	ediIAMSetup(t)
	config = Config{Driver: PGSQLDataProviderName, Host: "db", Port: 5432, Name: "edi", Username: "u", Password: "pw", SSLMode: 3}
	if !strings.Contains(getPGSQLConnectionString(false), "password='pw'") {
		t.Fatal("the default mode must keep the configured password")
	}
	config.AWSIAMAuth = true
	if strings.Contains(getPGSQLConnectionString(false), "password") {
		t.Fatal("IAM mode must not write a password key")
	}
}

// One token per physical connect, built by the real signer for host:port and the user, and
// sent as the password; the pool's recycle is shortened through the test variable.
func TestEDIIAMTokenPerPhysicalConnect(t *testing.T) {
	logPath := ediIAMSetup(t)
	s := ediStartFakePG(t)
	creds := &ediFakeCreds{secret: "fixture-secret-" + ediRandomHex(t), expires: time.Now().Add(time.Hour).Truncate(time.Second)}
	iamLoadAWSConfig = ediFakeAWS(creds, "eu-west-1")
	pgsqlConnMaxLifetime = 150 * time.Millisecond
	config = ediIAMConfig(s)
	if err := initializePGSQLProvider(); err != nil {
		t.Fatal(err)
	}
	p := provider.(*PGSQLProvider)
	deadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := p.checkAvailability(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	pwds, users := s.passwords()
	if len(pwds) < 4 {
		t.Fatalf("only %d physical connects across the shortened recycle", len(pwds))
	}
	a := p.iam
	if got := a.connectAttempts.Load(); got != int64(len(pwds)) || a.connects.Load() != got || a.builds.Load() != got {
		t.Fatalf("hook calls %d, connects %d, builds %d, server connects %d", got, a.connects.Load(), a.builds.Load(), len(pwds))
	}
	prefix := "localhost:" + strconv.Itoa(s.port) + "?Action=connect&DBUser=sftpgo_app&"
	for i, pw := range pwds {
		if users[i] != "sftpgo_app" || !strings.HasPrefix(pw, prefix) ||
			!strings.Contains(pw, "X-Amz-Credential="+ediIAMAccessKey+"%2F") ||
			!strings.Contains(pw, "%2Feu-west-1%2Frds-db%2Faws4_request") || !strings.Contains(pw, "X-Amz-Expires=900") {
			t.Fatalf("connect %d: user %q, password is not an RDS token for the endpoint", i, users[i])
		}
	}
	if !strings.Contains(a.counters(), "credentials_expire: "+creds.expires.UTC().Format(time.RFC3339)) {
		t.Fatalf("counters %q", a.counters())
	}
	log := ediReadLog(t, logPath)
	for _, secret := range append([]string{creds.secret}, pwds...) {
		if strings.Contains(log, secret) {
			t.Fatal("the log contains a token or the secret key")
		}
	}
	if strings.Contains(log, "iam auth: ") {
		t.Fatal("a failure line without a failure")
	}
	// Healthy observability: one snapshot for the one credential expiry, one debug line per
	// physical connect, with the final counters.
	if n := strings.Count(log, "iam auth credentials: expiry changed"); n != 1 {
		t.Fatalf("%d credential snapshots for one expiry", n)
	}
	if n := strings.Count(log, "iam auth connect ok, "); n != len(pwds) {
		t.Fatalf("%d connect-ok lines for %d connects", n, len(pwds))
	}
	if !strings.Contains(log, fmt.Sprintf("connect_attempts: %d, connects: %d, connect_failures: 0", len(pwds), len(pwds))) {
		t.Fatal("the final counters are not observable")
	}
}

// The driver refusal sits in the shared dispatch, so no other driver can run with the flag
// on, whatever entry point starts it; with the flag off, dispatch is unchanged.
func TestEDIIAMDispatchRefusesOtherDrivers(t *testing.T) {
	for _, driver := range []string{MemoryDataProviderName, SQLiteDataProviderName, MySQLDataProviderName,
		BoltDataProviderName, CockroachDataProviderName, "nosuchdriver"} {
		t.Run(driver, func(t *testing.T) {
			ediIAMSetup(t)
			base := t.TempDir()
			cnf := Config{Driver: driver, AWSIAMAuth: true, BackupsPath: "backups", Name: "edi"}
			entries := map[string]func() error{
				"createProvider":     func() error { config = cnf; return createProvider(base) },
				"Initialize":         func() error { return Initialize(cnf, base, false) },
				"InitializeDatabase": func() error { return InitializeDatabase(cnf, base) },
				"ResetDatabase":      func() error { return ResetDatabase(cnf, base) },
				"RevertDatabase":     func() error { return RevertDatabase(cnf, base, 1) },
			}
			for name, entry := range entries {
				provider = nil
				err := entry()
				if err == nil || !strings.Contains(err.Error(), `aws_iam_auth: requires the "postgresql" driver`) {
					t.Fatalf("%s: err=%v", name, err)
				}
				if provider != nil {
					t.Fatalf("%s: a provider was initialized", name)
				}
			}
		})
	}
	t.Run("flag off", func(t *testing.T) {
		ediIAMSetup(t)
		provider = nil
		config = Config{Driver: MemoryDataProviderName}
		if err := createProvider(t.TempDir()); err != nil {
			t.Fatal(err)
		}
		if _, ok := provider.(*MemoryProvider); !ok {
			t.Fatalf("provider %T", provider)
		}
	})
}

func TestEDIIAMFailuresAreClassifiedAndRedacted(t *testing.T) {
	logPath := ediIAMSetup(t)
	s := ediStartFakePG(t)
	creds := &ediFakeCreds{secret: "fixture-secret-" + ediRandomHex(t), expires: time.Now().Add(time.Hour)}
	iamLoadAWSConfig = ediFakeAWS(creds, "eu-west-1")
	config = ediIAMConfig(s)

	s.refuse.Store(true)
	err := initializePGSQLProvider()
	if err == nil {
		t.Fatal("a refused login must fail the startup ping")
	}
	pwds, _ := s.passwords()
	if len(pwds) == 0 {
		t.Fatal("no login reached the server")
	}
	log := ediReadLog(t, logPath)
	if !strings.Contains(log, "iam auth: connect failed, class: auth, sqlstate: 28P01") {
		t.Fatalf("no classified connect failure in the log")
	}
	creds.fail.Store(true)
	s.refuse.Store(false)
	err = initializePGSQLProvider()
	if err == nil || !errors.Is(err, errPGSQLIAMTokenBuild) {
		t.Fatalf("err=%v", err)
	}
	log = ediReadLog(t, logPath)
	if !strings.Contains(log, "iam auth: token build failed, class: credentials") {
		t.Fatal("no classified token build failure in the log")
	}
	if strings.Contains(log, "fixture: credentials unavailable") || strings.Contains(err.Error(), "fixture: credentials unavailable") {
		t.Fatal("the raw credentials error is not reduced to its class")
	}
	for _, secret := range append([]string{creds.secret}, pwds...) {
		if strings.Contains(log, secret) || strings.Contains(err.Error(), secret) {
			t.Fatal("a token or the secret key reached an error or the log")
		}
	}
}

// The failure signal: one line per failed token build or connect, with a stable prefix the
// alarm keys on, and none once the failure clears.
func TestEDIIAMFailureSignalFiresAndStops(t *testing.T) {
	logPath := ediIAMSetup(t)
	s := ediStartFakePG(t)
	// Already expired, so the cache refreshes on every build and a credentials failure shows.
	creds := &ediFakeCreds{secret: "fixture-secret-" + ediRandomHex(t), expires: time.Now().Add(-time.Second)}
	iamLoadAWSConfig = ediFakeAWS(creds, "eu-west-1")
	var signerFails atomic.Bool
	realBuild := iamBuildToken
	iamBuildToken = func(ctx context.Context, endpoint, region, user string, c aws.CredentialsProvider) (string, error) {
		if signerFails.Load() {
			return "", errors.New("fixture: signer failed")
		}
		return realBuild(ctx, endpoint, region, user, c)
	}
	config = ediIAMConfig(s)
	if err := initializePGSQLProvider(); err != nil {
		t.Fatal(err)
	}
	p := provider.(*PGSQLProvider)
	// No idle connections: every ping is one physical connect, so attempts are exact.
	p.dbHandle.SetMaxIdleConns(0)
	ping := func(n int, wantErr bool) {
		t.Helper()
		for range n {
			if err := p.checkAvailability(); (err != nil) != wantErr {
				t.Fatalf("ping err=%v, want error %v", err, wantErr)
			}
		}
	}
	lines := func(prefix string) int {
		return strings.Count(ediReadLog(t, logPath), prefix)
	}
	const buildFailed, connectFailed = "iam auth: token build failed", "iam auth: connect failed"
	ping(3, false)
	if lines(buildFailed) != 0 || lines(connectFailed) != 0 {
		t.Fatal("failure lines while healthy")
	}

	steps := []struct {
		name   string
		fail   func()
		heal   func()
		prefix string
		class  string
	}{
		{"credentials", func() { creds.fail.Store(true) }, func() { creds.fail.Store(false) }, buildFailed, "class: credentials, code: none"},
		{"signer", func() { signerFails.Store(true) }, func() { signerFails.Store(false) }, buildFailed, "class: signer, code: none"},
		{"refused login", func() { s.refuse.Store(true) }, func() { s.refuse.Store(false) }, connectFailed, "class: auth, sqlstate: 28P01"},
	}
	for _, st := range steps {
		before := lines(st.prefix)
		beforeRecovered := lines("iam auth recovered")
		st.fail()
		ping(4, true)
		if got := lines(st.prefix) - before; got != 4 {
			t.Fatalf("%s: %d %q lines for 4 failed connects", st.name, got, st.prefix)
		}
		if !strings.Contains(ediReadLog(t, logPath), st.prefix+", "+st.class) {
			t.Fatalf("%s: no %q line", st.name, st.class)
		}
		st.heal()
		ping(3, false)
		if lines(st.prefix)-before != 4 || lines("iam auth recovered")-beforeRecovered != 1 {
			t.Fatalf("%s: the signal did not stop with one recovery line", st.name)
		}
	}
	// The database is unreachable: a network-class connect failure.
	_ = s.ln.Close()
	before := lines(connectFailed)
	ping(2, true)
	if lines(connectFailed)-before != 2 || !strings.Contains(ediReadLog(t, logPath), connectFailed+", class: network") {
		t.Fatal("no network-class connect failure lines")
	}
	a := p.iam
	if a.buildFailures.Load() != 8 || a.connectFailures.Load() != 6 {
		t.Fatalf("counters %s", a.counters())
	}
	log := ediReadLog(t, logPath)
	if strings.Contains(log, "fixture: signer failed") || strings.Contains(log, "fixture: credentials unavailable") ||
		strings.Contains(log, creds.secret) {
		t.Fatal("raw errors or the secret key reached the log")
	}
	pwds, _ := s.passwords()
	for _, pw := range pwds {
		if strings.Contains(log, pw) {
			t.Fatal("a token reached the log")
		}
	}
}
