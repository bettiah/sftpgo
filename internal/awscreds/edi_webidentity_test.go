// Copyright (C) 2026 EDI Platform contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build edi

// Run file-scoped via edi/test.sh only.
package awscreds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// ediWebIdentityFields are the response elements the guard requires, in document order.
var ediWebIdentityFields = []string{"AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}

// ediWebIdentityBody renders an AssumeRoleWithWebIdentity response without the omitted
// element; "Credentials" drops the whole block and "body" sends an empty 200.
func ediWebIdentityBody(omit string) string {
	if omit == "body" {
		return ""
	}
	values := map[string]string{"AccessKeyId": "ASIAGUARDFIXTURE", "SecretAccessKey": "fixture-secret",
		"SessionToken": "fixture-session", "Expiration": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	var creds strings.Builder
	for _, f := range ediWebIdentityFields {
		if f != omit {
			fmt.Fprintf(&creds, "<%s>%s</%s>", f, values[f], f)
		}
	}
	block := "<Credentials>" + creds.String() + "</Credentials>"
	if omit == "Credentials" {
		block = ""
	}
	return `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult>` +
		block + `<AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/fixture/s</Arn><AssumedRoleId>AROAFIXTURE:s</AssumedRoleId></AssumedRoleUser>` +
		`</AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>fixture</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>`
}

// ediFakeWebIdentitySTS answers with the current omission ("" for a complete response).
func ediFakeWebIdentitySTS(t *testing.T) (*httptest.Server, *atomic.Value) {
	t.Helper()
	var omit atomic.Value
	omit.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, ediWebIdentityBody(omit.Load().(string)))
	}))
	t.Cleanup(srv.Close)
	return srv, &omit
}

// ediWebIdentityEnv isolates the SDK environment and selects web identity against endpoint.
func ediWebIdentityEnv(t *testing.T, endpoint string) {
	t.Helper()
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
	t.Setenv("AWS_REGION", "eu-west-1")
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/fixture")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", token)
	t.Setenv("AWS_ENDPOINT_URL_STS", endpoint)
}

func TestEDIValidateWebIdentityOutput(t *testing.T) {
	complete := func() *sts.AssumeRoleWithWebIdentityOutput {
		return &sts.AssumeRoleWithWebIdentityOutput{Credentials: &types.Credentials{AccessKeyId: aws.String("a"),
			SecretAccessKey: aws.String("s"), SessionToken: aws.String("t"), Expiration: aws.Time(time.Now())}}
	}
	if err := validateWebIdentityOutput(complete()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]*sts.AssumeRoleWithWebIdentityOutput{"nil output": nil, "no Credentials": {}}
	for _, f := range ediWebIdentityFields {
		nilField, emptyField := complete(), complete()
		switch f {
		case "AccessKeyId":
			nilField.Credentials.AccessKeyId, emptyField.Credentials.AccessKeyId = nil, aws.String("")
		case "SecretAccessKey":
			nilField.Credentials.SecretAccessKey, emptyField.Credentials.SecretAccessKey = nil, aws.String("")
		case "SessionToken":
			nilField.Credentials.SessionToken, emptyField.Credentials.SessionToken = nil, aws.String("")
		case "Expiration":
			nilField.Credentials.Expiration, emptyField = nil, nil
		}
		cases["nil "+f] = nilField
		if emptyField != nil {
			cases["empty "+f] = emptyField
		}
	}
	for name, out := range cases {
		if err := validateWebIdentityOutput(out); !errors.Is(err, ErrIncompleteWebIdentityResponse) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}

// Through the real loader: an empty 200 or any missing field is an ordinary error, not a
// panic in the cache's refresh goroutine (which would end this test binary), and the same
// credentials provider recovers once STS answers completely.
func TestEDIGuardedWebIdentityLoader(t *testing.T) {
	srv, omit := ediFakeWebIdentitySTS(t)
	ediWebIdentityEnv(t, srv.URL)
	cfg, err := config.LoadDefaultConfig(context.Background(), GuardWebIdentity())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range append([]string{"body", "Credentials"}, ediWebIdentityFields...) {
		omit.Store(mode)
		if _, err := cfg.Credentials.Retrieve(context.Background()); !errors.Is(err, ErrIncompleteWebIdentityResponse) {
			t.Fatalf("omit %s: err=%v", mode, err)
		}
	}
	omit.Store("")
	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil || creds.AccessKeyID != "ASIAGUARDFIXTURE" || !creds.CanExpire {
		t.Fatalf("no recovery: %v", err)
	}
}
