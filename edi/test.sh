#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source edi/build-inputs.env
export GOTOOLCHAIN=$SFTPGO_GO_VERSION GOFLAGS=-mod=readonly
# File-scoped: upstream package TestMain starts unrelated providers/listeners.
go test -race -tags "$SFTPGO_BUILD_TAGS" internal/sftpd/transfer.go internal/sftpd/stored_extent_test.go
go test -race -tags "nos3,$SFTPGO_BUILD_TAGS" internal/sftpd/transfer.go internal/sftpd/stored_extent_test.go
