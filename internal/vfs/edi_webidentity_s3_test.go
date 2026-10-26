// Copyright (C) 2026 EDI Platform contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !nos3

package vfs

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sftpgo/sdk"
)

func ediIncompleteWebIdentityBody(omit string) string {
	if omit == "body" {
		return ""
	}
	elements := []string{"<AccessKeyId>ASIAS3GUARD</AccessKeyId>", "<SecretAccessKey>fixture-secret</SecretAccessKey>",
		"<SessionToken>fixture-session</SessionToken>", "<Expiration>" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + "</Expiration>"}
	var kept []string
	for _, e := range elements {
		if !strings.HasPrefix(e, "<"+omit+">") {
			kept = append(kept, e)
		}
	}
	creds := "<Credentials>" + strings.Join(kept, "") + "</Credentials>"
	if omit == "Credentials" {
		creds = ""
	}
	return `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult>` +
		creds + `</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`
}

// The S3 filesystem's default credential chain under IRSA: an incomplete AssumeRoleWithWebIdentity
// 200 fails the S3 call before any request reaches S3, instead of crashing the process, and
// the same filesystem recovers once STS answers completely.
func TestEDIS3WebIdentityGuard(t *testing.T) {
	var omit atomic.Value
	omit.Store("")
	stsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, ediIncompleteWebIdentityBody(omit.Load().(string)))
	}))
	t.Cleanup(stsSrv.Close)
	var s3Requests atomic.Int64
	var signedWithSTS atomic.Bool
	s3Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s3Requests.Add(1)
		signedWithSTS.Store(strings.Contains(r.Header.Get("Authorization"), "Credential=ASIAS3GUARD/"))
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(s3Srv.Close)

	dir := t.TempDir()
	for _, name := range []string{"AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CA_BUNDLE", "AWS_ENDPOINT_URL"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("fixture-web-identity-token"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", dir)
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "none"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/fixture")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", token)
	t.Setenv("AWS_ENDPOINT_URL_STS", stsSrv.URL)

	fs, err := NewS3Fs("edi-guard", dir, "", S3FsConfig{BaseS3FsConfig: sdk.BaseS3FsConfig{
		Bucket: "bucket", Region: "eu-west-1", Endpoint: s3Srv.URL, ForcePathStyle: true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"body", "Credentials", "AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"} {
		omit.Store(mode)
		if _, err := fs.Stat("/key"); err == nil || !strings.Contains(err.Error(), "AssumeRoleWithWebIdentity response is incomplete") {
			t.Fatalf("omit %s: err=%v", mode, err)
		}
	}
	if s3Requests.Load() != 0 {
		t.Fatal("an S3 request was sent without credentials")
	}
	omit.Store("")
	if _, err := fs.Stat("/key"); err == nil || !fs.IsNotExist(err) {
		t.Fatalf("after recovery: err=%v", err)
	}
	if s3Requests.Load() == 0 || !signedWithSTS.Load() {
		t.Fatal("the recovered request was not signed with the refreshed credentials")
	}
}
