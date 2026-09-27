package sftpd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/rs/zerolog"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/command"
	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/httpclient"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sftpgo/sdk"
	"golang.org/x/crypto/ssh"
)

func ediAuthSetup(t *testing.T, hook string) {
	t.Helper()
	if err := (&kms.Configuration{}).Initialize(); err != nil {
		t.Fatal(err)
	}
	cfg := dataprovider.Config{Driver: dataprovider.MemoryDataProviderName, BackupsPath: t.TempDir(), ExternalAuthHook: hook, PasswordHashing: dataprovider.PasswordHashing{Algo: dataprovider.HashingAlgoBcrypt, BcryptOptions: dataprovider.BcryptOptions{Cost: 4}}}
	// Initialize starts a zero-delay quota goroutine; Close does not join it.
	// Wait for its final log before a later test can replace the global provider.
	quotaDone := make(chan struct{})
	oldLogger := *logger.GetLogger()
	*logger.GetLogger() = zerolog.New(io.Discard).Hook(zerolog.HookFunc(func(_ *zerolog.Event, _ zerolog.Level, msg string) {
		if strings.HasPrefix(msg, "delayed quota update loop ended") {
			close(quotaDone)
		}
	}))
	if err := dataprovider.Initialize(cfg, t.TempDir(), false); err != nil {
		t.Fatal(err)
	}
	<-quotaDone
	*logger.GetLogger() = oldLogger
	t.Cleanup(func() { dataprovider.Close() })
	if err := (command.Config{Timeout: 1}).Initialize(); err != nil {
		t.Fatal(err)
	}
	hc := httpclient.Config{Timeout: 0.1}
	if err := hc.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := common.Initialize(common.Configuration{DefenderConfig: common.DefenderConfig{Enabled: true, Driver: common.DefenderDriverMemory, BanTime: 1, BanTimeIncrement: 1, Threshold: 100, ScoreValid: 2, ScoreInvalid: 3, ScoreNoAuth: 0, ObservationTime: 1, EntriesSoftLimit: 10, EntriesHardLimit: 20}}, 0); err != nil {
		t.Fatal(err)
	}
}
func ediSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func ediServerConfig(t *testing.T, c *Configuration) *ssh.ServerConfig {
	t.Helper()
	s := c.getServerConfig()
	s.AddHostKey(ediSigner(t))
	return s
}
func ediScore(t *testing.T, want int) {
	t.Helper()
	got, err := common.GetDefenderScore("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("defender score=%d want %d", got, want)
	}
}
func ediGauge(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "sftpgo_ssh_preauth_connections" {
			if len(f.Metric) != 1 || len(f.Metric[0].Label) != 0 {
				t.Fatal("preauth gauge must be unlabelled")
			}
			return f.Metric[0].GetGauge().GetValue()
		}
	}
	t.Fatal("missing preauth gauge")
	return 0
}
func ediWait(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for condition")
		}
		time.Sleep(time.Millisecond)
	}
}

// Buffered net.Pipe endpoints model socket writes without opening a listener.
// SSH can write KEX packets simultaneously; unbuffered net.Pipe would deadlock.
type ediAddrConn struct {
	net.Conn
	writes   chan []byte
	stop     chan struct{}
	once     sync.Once
	pumpDone chan struct{}
}

func ediBuffered(conn net.Conn) *ediAddrConn {
	c := &ediAddrConn{Conn: conn, writes: make(chan []byte, 64), stop: make(chan struct{}), pumpDone: make(chan struct{})}
	go func() {
		defer close(c.pumpDone)
		for {
			select {
			case p := <-c.writes:
				if _, err := conn.Write(p); err != nil {
					return
				}
			case <-c.stop:
				return
			}
		}
	}()
	return c
}
func (c *ediAddrConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}
func (c *ediAddrConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2022}
}
func (c *ediAddrConn) Write(p []byte) (int, error) {
	select {
	case c.writes <- append([]byte(nil), p...):
		return len(p), nil
	case <-c.stop:
		return 0, net.ErrClosed
	}
}
func (c *ediAddrConn) Close() error {
	c.once.Do(func() { close(c.stop); c.Conn.Close() })
	<-c.pumpDone
	return nil
}
func ediAccepted(t *testing.T, c *Configuration, s *ssh.ServerConfig) (net.Conn, <-chan struct{}) {
	t.Helper()
	a, b := net.Pipe()
	server, client := ediBuffered(a), ediBuffered(b)
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); c.AcceptInboundConnection(server, s) }()
	t.Cleanup(func() {
		client.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("accept goroutine leaked")
		}
	})
	return client, done
}
func ediClient(t *testing.T, conn net.Conn, methods ...ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	sc, ch, req, err := ssh.NewClientConn(conn, "fixture", &ssh.ClientConfig{User: "partner", Auth: methods, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return ssh.NewClient(sc, ch, req), nil
}
func ediWaitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("SSH handler did not finish")
	}
}

func TestEDIExternalAuthProgramScoring(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		score      int
	}{
		{"program-failure", "exit 1", 0},
		{"program-timeout", "exec /bin/sleep 5", 0},
		{"invalid-json", "printf 'not-json'", 0},
		{"post-accept-add-validation", `printf '{"username":"partner","home_dir":"relative"}'`, 0},
		{"reject", "printf '{}'", 2},
	} {
		for _, method := range []string{"password", "publickey"} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				hook := filepath.Join(t.TempDir(), "auth")
				if err := os.WriteFile(hook, []byte("#!/bin/sh\n"+tc.body+"\n"), 0700); err != nil {
					t.Fatal(err)
				}
				ediAuthSetup(t, hook)
				c := &Configuration{PasswordAuthentication: true, HandshakeTimeout: 2}
				s := ediServerConfig(t, c)
				conn, done := ediAccepted(t, c, s)
				auth := ssh.Password("password")
				if method == "publickey" {
					auth = ssh.PublicKeys(ediSigner(t))
				}
				client, err := ediClient(t, conn, auth)
				if err == nil {
					client.Close()
					t.Fatal("hook failure authenticated")
				}
				conn.Close()
				ediWaitDone(t, done)
				ediScore(t, tc.score)
			})
		}
	}
}

// Exercise the real HTTP transport, server and timeout path over net.Pipe.
// The sandbox cannot bind loopback listeners; no production hook seam is added.
type ediPipeListener struct {
	incoming chan net.Conn
	stopped  chan struct{}
	once     sync.Once
}

func (l *ediPipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.incoming:
		return c, nil
	case <-l.stopped:
		return nil, net.ErrClosed
	}
}
func (l *ediPipeListener) Close() error { l.once.Do(func() { close(l.stopped) }); return nil }
func (l *ediPipeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

type ediHookServer struct {
	URL      string
	server   *http.Server
	listener *ediPipeListener
	done     chan struct{}
}

func (h *ediHookServer) Close() { h.listener.Close(); h.server.Close(); <-h.done }
func ediHTTPHook(t *testing.T, handler http.Handler) *ediHookServer {
	t.Helper()
	listener := &ediPipeListener{incoming: make(chan net.Conn), stopped: make(chan struct{})}
	h := &ediHookServer{URL: "http://hook.invalid/auth", server: &http.Server{Handler: handler}, listener: listener, done: make(chan struct{})}
	go func() { defer close(h.done); h.server.Serve(listener) }()
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		a, b := net.Pipe()
		select {
		case <-listener.stopped:
			a.Close()
			b.Close()
			return nil, net.ErrClosed
		default:
		}
		select {
		case listener.incoming <- a:
			return b, nil
		case <-listener.stopped:
			a.Close()
			b.Close()
			return nil, net.ErrClosed
		case <-ctx.Done():
			a.Close()
			b.Close()
			return nil, ctx.Err()
		}
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { h.Close(); transport.CloseIdleConnections(); http.DefaultTransport = original })
	return h
}

func TestEDIExternalAuthHTTPScoring(t *testing.T) {
	for _, mode := range []string{"down", "503", "timeout", "invalid-json", "post-accept", "reject", "mixed"} {
		for _, method := range []string{"password", "publickey"} {
			if mode == "mixed" && method != "publickey" {
				continue
			}
			t.Run(mode+"/"+method, func(t *testing.T) {
				var calls atomic.Int32
				hook := ediHTTPHook(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					n := calls.Add(1)
					switch mode {
					case "503":
						w.WriteHeader(503)
					case "timeout":
						<-r.Context().Done()
					case "invalid-json":
						fmt.Fprint(w, "bad JSON")
					case "post-accept":
						fmt.Fprint(w, `{"username":"partner","home_dir":"relative"}`)
					case "mixed":
						if n == 1 {
							w.WriteHeader(503)
						} else {
							fmt.Fprint(w, "{}")
						}
					default:
						fmt.Fprint(w, "{}")
					}
				}))
				defer hook.Close()
				if mode == "down" {
					hook.Close()
				}
				ediAuthSetup(t, hook.URL)
				c := &Configuration{PasswordAuthentication: true, HandshakeTimeout: 2}
				conn, done := ediAccepted(t, c, ediServerConfig(t, c))
				auth := ssh.Password("password")
				if method == "publickey" {
					auth = ssh.PublicKeys(ediSigner(t), ediSigner(t))
				}
				client, err := ediClient(t, conn, auth)
				if err == nil {
					client.Close()
					t.Fatal("hook failure authenticated")
				}
				conn.Close()
				ediWaitDone(t, done)
				want := 0
				if mode == "reject" || mode == "mixed" {
					want = 2
				}
				ediScore(t, want)
			})
		}
	}
}

func TestEDIExternalAuthClassificationAndMixedScoring(t *testing.T) {
	hook := filepath.Join(t.TempDir(), "auth")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nprintf 'invalid json'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ediAuthSetup(t, hook)
	_, err := dataprovider.CheckUserAndPass("partner", "password", "127.0.0.1", common.ProtocolSSH)
	if !errors.Is(err, dataprovider.ErrExternalAuthUnavailable) {
		t.Fatalf("classification: %v", err)
	}
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatalf("JSON cause lost: %v", err)
	}
	for _, method := range []string{dataprovider.LoginMethodPassword, dataprovider.SSHLoginMethodKeyboardInteractive} {
		updateLoginMetrics(&dataprovider.User{}, "127.0.0.1", method, err)
		ediScore(t, 0)
	}
	unavailable := newAuthenticationError(err, dataprovider.SSHLoginMethodPublicKey, "partner")
	rejected := newAuthenticationError(dataprovider.ErrInvalidCredentials, dataprovider.SSHLoginMethodPublicKey, "partner")
	checkAuthError("127.0.0.1", &ssh.ServerAuthError{Errors: []error{unavailable, unavailable}})
	ediScore(t, 0)
	checkAuthError("127.0.0.1", &ssh.ServerAuthError{Errors: []error{unavailable, rejected, rejected}})
	ediScore(t, 2)
}

func TestEDIExternalAuthPostAcceptUpdate(t *testing.T) {
	hook := filepath.Join(t.TempDir(), "auth")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nprintf '{\"username\":\"partner\",\"home_dir\":\"relative\"}'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ediAuthSetup(t, hook)
	user := dataprovider.User{BaseUser: sdk.BaseUser{Username: "partner", Password: "password", HomeDir: t.TempDir(), Status: 1, Permissions: map[string][]string{"/": {dataprovider.PermAny}}}}
	if err := dataprovider.AddUser(&user, "test", "", ""); err != nil {
		t.Fatal(err)
	}
	_, err := dataprovider.CheckUserAndPass("partner", "password", "127.0.0.1", common.ProtocolSSH)
	if !errors.Is(err, dataprovider.ErrExternalAuthUnavailable) {
		t.Fatalf("post-accept update classification=%v", err)
	}
	updateLoginMetrics(&user, "127.0.0.1", dataprovider.LoginMethodPassword, err)
	ediScore(t, 0)
}

func TestEDIHandshakeTimeoutValidation(t *testing.T) {
	for _, n := range []int{-1, 1, 5, 9} {
		c := Configuration{HandshakeTimeout: n}
		if err := c.validateHandshakeTimeout(); err == nil || !strings.Contains(err.Error(), "sftpd.handshake_timeout") {
			t.Fatalf("accepted invalid timeout %d: %v", n, err)
		}
		// Must reject before attempting to use an uninitialized provider.
		if _, err := c.startServing(t.TempDir()); err == nil || !strings.Contains(err.Error(), "sftpd.handshake_timeout") {
			t.Fatalf("startup validation order: %v", err)
		}
	}
	for _, n := range []int{0, 10, 120} {
		c := Configuration{HandshakeTimeout: n}
		if err := c.validateHandshakeTimeout(); err != nil {
			t.Fatal(err)
		}
		want := time.Duration(n) * time.Second
		if n == 0 {
			want = 120 * time.Second
		}
		if c.getHandshakeTimeout() != want {
			t.Fatalf("timeout %d = %v", n, c.getHandshakeTimeout())
		}
	}
}
func TestEDIHandshakeDeadlineAndPreauthGauge(t *testing.T) {
	ediAuthSetup(t, "")
	c := &Configuration{HandshakeTimeout: 1, PasswordAuthentication: true}
	conn, done := ediAccepted(t, c, ediServerConfig(t, c))
	defer conn.Close()
	ediWait(t, func() bool { return ediGauge(t) == 1 })
	start := time.Now()
	ediWaitDone(t, done)
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Fatalf("deadline took %s", elapsed)
	}
	if ediGauge(t) != 0 {
		t.Fatal("preauth leaked after deadline")
	}
}
func TestEDIPreauthGaugeExits(t *testing.T) {
	for _, mode := range []string{"close", "refused", "panic", "success", "kex-error"} {
		t.Run(mode, func(t *testing.T) {
			ediAuthSetup(t, "")
			c := &Configuration{HandshakeTimeout: 2, PasswordAuthentication: true}
			s := ediServerConfig(t, c)
			if mode == "refused" {
				common.Config.MaxTotalConnections = 1
				common.Connections.AddClientConnection("other")
				defer common.Connections.RemoveClientConnection("other")
			}
			if mode == "panic" {
				s.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { panic("injected callback panic") }
			}
			if mode == "success" {
				user := dataprovider.User{BaseUser: sdk.BaseUser{Username: "partner", HomeDir: t.TempDir(), Status: 1, Password: "password", Permissions: map[string][]string{"/": {dataprovider.PermAny}}}}
				if err := dataprovider.AddUser(&user, "test", "", ""); err != nil {
					t.Fatal(err)
				}
			}
			conn, done := ediAccepted(t, c, s)
			switch mode {
			case "kex-error":
				conn.Write([]byte("invalid SSH identification\r\n"))
			case "close":
				ediWait(t, func() bool { return ediGauge(t) == 1 })
				conn.Close()
			case "success", "panic":
				client, err := ediClient(t, conn, ssh.Password("password"))
				if mode == "success" {
					if err != nil {
						t.Fatal(err)
					}
					ediWait(t, func() bool { return ediGauge(t) == 0 })
					if _, _, err := client.SendRequest("keepalive", true, nil); err != nil {
						t.Fatal("authenticated connection closed:", err)
					}
					client.Close()
					ediScore(t, 0)
				} else if err == nil {
					client.Close()
					t.Fatal("panic authenticated")
				}
			}
			ediWaitDone(t, done)
			if ediGauge(t) != 0 {
				t.Fatal("preauth gauge leaked")
			}
		})
	}
}
