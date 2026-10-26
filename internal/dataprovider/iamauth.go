// Copyright (C) 2026 EDI Platform contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !nopgsql

package dataprovider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/drakkan/sftpgo/v2/internal/logger"
)

// RDS IAM database authentication for the PostgreSQL provider (data_provider.aws_iam_auth).
// Every physical connection gets a freshly built auth token as its password; nothing else
// may supply a password.

// pgsqlIAMAllowedKeys are the only keys an IAM-mode connection string may carry: those that
// getPGSQLConnectionString writes, except password, plus default_query_exec_mode. passfile,
// service and servicefile are absent, so the string cannot name another credential source.
var pgsqlIAMAllowedKeys = []string{"host", "port", "dbname", "user", "sslmode", "connect_timeout",
	"sslrootcert", "sslcert", "sslkey", "sslsni", "target_session_attrs", "default_query_exec_mode"}

// pgsqlIAMRefusedEnv are the libpq variables that can supply a password or a service definition.
var pgsqlIAMRefusedEnv = []string{"PGPASSWORD", "PGPASSFILE", "PGSERVICE", "PGSERVICEFILE"}

var errPGSQLIAMTokenBuild = errors.New("unable to build the RDS IAM auth token")

// Package variables so that tests can shorten or replace them; production never changes them.
//
// The AWS credentials cache runs a refresh under a context without deadline or cancellation,
// shared by every waiter, and the SDK's default HTTP client has no overall or response
// timeout. A refresh against an endpoint that accepts the connection and never answers would
// therefore stay pending, and every later connect would wait on it. The STS client used here
// gets finite connect, response and request timeouts and a bounded number of attempts, so a
// refresh always ends (worst case about iamSTSMaxAttempts × iamSTSRequestTimeout plus one
// retry backoff of at most a second) and the next connect after the network recovers starts
// a fresh one. iamTokenTimeout separately bounds how long a connect waits in the hook, which
// pgx runs before its own connect_timeout applies.
var (
	iamTokenTimeout       = 10 * time.Second
	iamSTSConnectTimeout  = 2 * time.Second
	iamSTSResponseTimeout = 3 * time.Second
	iamSTSRequestTimeout  = 4 * time.Second
	iamSTSMaxAttempts     = 2
	iamLoadAWSConfig      = func(ctx context.Context, region string) (aws.Config, error) {
		opts := []func(*awsconfig.LoadOptions) error{
			awsconfig.WithHTTPClient(newIAMHTTPClient()),
			awsconfig.WithRetryMaxAttempts(iamSTSMaxAttempts),
		}
		if region != "" {
			opts = append(opts, awsconfig.WithRegion(region))
		}
		return awsconfig.LoadDefaultConfig(ctx, opts...)
	}
	iamBuildToken = func(ctx context.Context, endpoint, region, dbUser string, creds aws.CredentialsProvider) (string, error) {
		return auth.BuildAuthToken(ctx, endpoint, region, dbUser, creds)
	}
)

// newIAMHTTPClient returns the credential client: a buildable client, so that AWS_CA_BUNDLE
// still applies, with every network phase bounded.
func newIAMHTTPClient() *awshttp.BuildableClient {
	return awshttp.NewBuildableClient().
		WithTimeout(iamSTSRequestTimeout).
		WithDialerOptions(func(d *net.Dialer) {
			d.Timeout = iamSTSConnectTimeout
		}).
		WithTransportOptions(func(tr *http.Transport) {
			tr.TLSHandshakeTimeout = iamSTSConnectTimeout
			tr.ResponseHeaderTimeout = iamSTSResponseTimeout
		})
}

type pgsqlIAMAuth struct {
	region string
	creds  aws.CredentialsProvider
	// The single verified-full host, for the startup log line.
	host string
	port uint16
	user string

	connectAttempts atomic.Int64
	connects        atomic.Int64
	connectFailures atomic.Int64
	builds          atomic.Int64
	buildFailures   atomic.Int64
	// Unix seconds of the credentials used by the last successful build, 0 if they never expire.
	credentialsExpire atomic.Int64
	// Set by a failure and cleared, with one recovery line, by the next success.
	buildFailing   atomic.Bool
	connectFailing atomic.Bool
}

// checkPGSQLIAMEnv refuses libpq variables that would supply a password or a service.
func checkPGSQLIAMEnv() error {
	for _, name := range pgsqlIAMRefusedEnv {
		if _, ok := os.LookupEnv(name); ok {
			return fmt.Errorf("aws_iam_auth: %s is set; IAM authentication accepts no other password source", name)
		}
	}
	return nil
}

// checkPGSQLIAMConnConfig applies the IAM refusals to the effective, parsed configuration,
// which already includes environment defaults, ~/.pgpass and any service file.
func checkPGSQLIAMConnConfig(cfg *pgx.ConnConfig) error {
	if cfg.Password != "" {
		return errors.New("aws_iam_auth: the effective configuration has a password (connection settings, passfile or service file); IAM authentication accepts none")
	}
	if len(cfg.Fallbacks) > 0 {
		return errors.New("aws_iam_auth: the effective configuration has more than one host or a TLS fallback; exactly one host with sslmode verify-full is required")
	}
	tc := cfg.TLSConfig
	if tc == nil || tc.InsecureSkipVerify || tc.ServerName == "" || tc.VerifyPeerCertificate != nil {
		return errors.New("aws_iam_auth: TLS is not verify-full; sslmode verify-full is required")
	}
	return nil
}

// parsePGSQLIAMConfig parses the connection settings with the IAM key allow-list and refusals.
func parsePGSQLIAMConfig() (*pgx.ConnConfig, error) {
	if config.Driver != PGSQLDataProviderName {
		return nil, fmt.Errorf("aws_iam_auth: requires the %q driver", PGSQLDataProviderName)
	}
	if config.Password != "" {
		return nil, errors.New("aws_iam_auth: data_provider.password is set; IAM authentication accepts no other password source")
	}
	if err := checkPGSQLIAMEnv(); err != nil {
		return nil, err
	}
	cfg, err := pgx.ParseConfigWithOptions(getPGSQLConnectionString(false), pgx.ParseConfigOptions{
		ParseConfigOptions: pgconn.ParseConfigOptions{ConnStringAllowedKeys: pgsqlIAMAllowedKeys},
	})
	if err != nil {
		var parseErr *pgconn.ParseConfigError
		if errors.As(err, &parseErr) {
			// The error quotes the connection string with best-effort redaction only.
			parseErr.ConnString = "[redacted]"
		}
		return nil, fmt.Errorf("aws_iam_auth: invalid connection settings: %w", err)
	}
	if err := checkPGSQLIAMConnConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func newPGSQLIAMAuth(cfg *pgx.ConnConfig) (*pgsqlIAMAuth, error) {
	ctx, cancel := context.WithTimeout(context.Background(), iamTokenTimeout)
	defer cancel()

	awsCfg, err := iamLoadAWSConfig(ctx, config.AWSIAMRegion)
	if err != nil {
		return nil, fmt.Errorf("aws_iam_auth: unable to load the AWS SDK configuration: %w", err)
	}
	if awsCfg.Region == "" {
		return nil, errors.New("aws_iam_auth: no AWS region; set data_provider.aws_iam_region or AWS_REGION")
	}
	if awsCfg.Credentials == nil {
		return nil, errors.New("aws_iam_auth: the AWS SDK configuration has no credentials provider")
	}
	creds := awsCfg.Credentials
	if _, ok := creds.(*aws.CredentialsCache); !ok {
		creds = aws.NewCredentialsCache(creds)
	}
	return &pgsqlIAMAuth{
		region: awsCfg.Region,
		creds:  creds,
		host:   cfg.Host,
		port:   cfg.Port,
		user:   cfg.User,
	}, nil
}

// token builds an auth token for host:port and user. It never returns or logs the token
// with any error, and errors carry only a failure class.
func (a *pgsqlIAMAuth) token(ctx context.Context, host string, port uint16, user string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, iamTokenTimeout)
	defer cancel()

	a.builds.Add(1)
	creds, err := a.creds.Retrieve(ctx)
	class := "credentials"
	var token string
	if err == nil {
		expire := int64(0)
		if creds.CanExpire {
			expire = creds.Expires.Unix()
		}
		a.credentialsExpire.Store(expire)
		frozen := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return creds, nil })
		class = "signer"
		token, err = iamBuildToken(ctx, net.JoinHostPort(host, strconv.Itoa(int(port))), a.region, user, frozen)
	}
	if err != nil {
		a.buildFailures.Add(1)
		a.buildFailing.Store(true)
		class, code := classifyIAMBuildError(err, class)
		providerLog(logger.LevelError, "iam auth: token build failed, class: %s, code: %s, %s", class, code, a.counters())
		return "", fmt.Errorf("%w (class %s)", errPGSQLIAMTokenBuild, class)
	}
	if a.buildFailing.Swap(false) {
		providerLog(logger.LevelInfo, "iam auth recovered: token build succeeded, %s", a.counters())
	}
	return token, nil
}

// beforeConnect keeps the provider's host randomisation and sets a fresh token as the password.
func (a *pgsqlIAMAuth) beforeConnect(ctx context.Context, cc *pgx.ConnConfig) error {
	a.connectAttempts.Add(1)
	if err := stdlib.RandomizeHostOrderFunc(ctx, cc); err != nil {
		return err
	}
	token, err := a.token(ctx, cc.Host, cc.Port, cc.User)
	if err != nil {
		return err
	}
	cc.Password = token
	return nil
}

func (a *pgsqlIAMAuth) counters() string {
	expire := "none"
	if v := a.credentialsExpire.Load(); v > 0 {
		expire = time.Unix(v, 0).UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("builds: %d, build_failures: %d, connect_attempts: %d, connects: %d, connect_failures: %d, credentials_expire: %s",
		a.builds.Load(), a.buildFailures.Load(), a.connectAttempts.Load(), a.connects.Load(), a.connectFailures.Load(), expire)
}

// pgsqlIAMConnector counts client-side physical connects and logs connect failures by class.
type pgsqlIAMConnector struct {
	driver.Connector
	auth *pgsqlIAMAuth
}

func (c *pgsqlIAMConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		// A failed token build is already counted and logged once, as a build failure.
		if !errors.Is(err, errPGSQLIAMTokenBuild) {
			c.auth.connectFailures.Add(1)
			c.auth.connectFailing.Store(true)
			class, code := classifyIAMConnectError(err)
			providerLog(logger.LevelError, "iam auth: connect failed, class: %s, sqlstate: %s, %s", class, code, c.auth.counters())
		}
		return nil, err
	}
	c.auth.connects.Add(1)
	if c.auth.connectFailing.Swap(false) {
		providerLog(logger.LevelInfo, "iam auth recovered: connect succeeded, %s", c.auth.counters())
	}
	return conn, nil
}

func openPGSQLIAMHandle(cfg *pgx.ConnConfig, a *pgsqlIAMAuth) *sql.DB {
	connector := stdlib.GetConnector(*cfg, stdlib.OptionBeforeConnect(a.beforeConnect))
	return sql.OpenDB(&pgsqlIAMConnector{Connector: connector, auth: a})
}

func classifyIAMBuildError(err error, stage string) (string, string) {
	code := "none"
	var apiErr interface{ ErrorCode() string }
	if errors.As(err, &apiErr) {
		code = apiErr.ErrorCode()
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return "timeout", code
	}
	if errors.Is(err, context.Canceled) {
		return "canceled", code
	}
	return stage, code
}

func classifyIAMConnectError(err error) (string, string) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if strings.HasPrefix(pgErr.Code, "28") {
			return "auth", pgErr.Code
		}
		return "server", pgErr.Code
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout", "none"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled", "none"
	}
	var certErr *tls.CertificateVerificationError
	var hostErr x509.HostnameError
	var authorityErr x509.UnknownAuthorityError
	var recordErr tls.RecordHeaderError
	if errors.As(err, &certErr) || errors.As(err, &hostErr) || errors.As(err, &authorityErr) || errors.As(err, &recordErr) {
		return "tls", "none"
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout", "none"
		}
		return "network", "none"
	}
	return "other", "none"
}
