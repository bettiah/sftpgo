// Copyright (C) 2026 EDI Platform contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package awscreds guards the AWS SDK's web identity credential source (EDI).
//
// The pinned SDK's web identity provider dereferences the AssumeRoleWithWebIdentity
// output's Credentials and Expiration without checking them. A 200 response without them,
// such as an empty body from an intercepting proxy, panics inside the credentials cache's
// refresh goroutine, where it cannot be recovered, and ends the process. GuardWebIdentity
// validates the output before the provider reads it, so such a response is an ordinary
// error and the next retrieval tries again.
package awscreds

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ErrIncompleteWebIdentityResponse reports an AssumeRoleWithWebIdentity success response
// that lacks a credential field.
var ErrIncompleteWebIdentityResponse = errors.New("AssumeRoleWithWebIdentity response is incomplete")

// GuardWebIdentity returns a LoadDefaultConfig option that validates every
// AssumeRoleWithWebIdentity response before the SDK's web identity provider reads it.
func GuardWebIdentity() func(*config.LoadOptions) error {
	return config.WithWebIdentityRoleCredentialOptions(func(o *stscreds.WebIdentityRoleOptions) {
		// The loader applies these options twice: first without a client (it then builds the
		// STS client), then inside NewWebIdentityRoleProvider with that client set.
		if o.Client == nil {
			return
		}
		if _, ok := o.Client.(validatingClient); !ok {
			o.Client = validatingClient{next: o.Client}
		}
	})
}

type validatingClient struct {
	next stscreds.AssumeRoleWithWebIdentityAPIClient
}

func (c validatingClient) AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput,
	optFns ...func(*sts.Options),
) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	out, err := c.next.AssumeRoleWithWebIdentity(ctx, params, optFns...)
	if err != nil {
		return out, err
	}
	if err := validateWebIdentityOutput(out); err != nil {
		return nil, err
	}
	return out, nil
}

func validateWebIdentityOutput(out *sts.AssumeRoleWithWebIdentityOutput) error {
	if out == nil || out.Credentials == nil {
		return fmt.Errorf("%w: no Credentials", ErrIncompleteWebIdentityResponse)
	}
	c := out.Credentials
	switch {
	case c.AccessKeyId == nil || *c.AccessKeyId == "":
		return fmt.Errorf("%w: no AccessKeyId", ErrIncompleteWebIdentityResponse)
	case c.SecretAccessKey == nil || *c.SecretAccessKey == "":
		return fmt.Errorf("%w: no SecretAccessKey", ErrIncompleteWebIdentityResponse)
	case c.SessionToken == nil || *c.SessionToken == "":
		return fmt.Errorf("%w: no SessionToken", ErrIncompleteWebIdentityResponse)
	case c.Expiration == nil:
		return fmt.Errorf("%w: no Expiration", ErrIncompleteWebIdentityResponse)
	}
	return nil
}
