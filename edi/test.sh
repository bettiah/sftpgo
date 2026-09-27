#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source edi/build-inputs.env
export GOTOOLCHAIN=$SFTPGO_GO_VERSION GOFLAGS=-mod=readonly
# Tests that initialize process globals must be tag-isolated from upstream suites.
# File-scoped: upstream package TestMain starts unrelated providers/listeners.
go test -race -tags "edi,$SFTPGO_BUILD_TAGS" internal/sftpd/transfer.go internal/sftpd/stored_extent_test.go
go test -race -tags "edi,nos3,$SFTPGO_BUILD_TAGS" internal/sftpd/transfer.go internal/sftpd/stored_extent_test.go
go test -race -tags "$SFTPGO_BUILD_TAGS" ./internal/vfs -run '^TestS3(Upload|Complete|Read|Credential)'
go test -race -tags "$SFTPGO_BUILD_TAGS" ./internal/vfs -run '^TestEDIStaging'
go test -race -tags "$SFTPGO_BUILD_TAGS" internal/common/actions.go internal/common/clientsmap.go internal/common/common.go internal/common/connection.go internal/common/dataretention.go internal/common/defender.go internal/common/defenderdb.go internal/common/defendermem.go internal/common/eventmanager.go internal/common/eventscheduler.go internal/common/httpauth.go internal/common/ratelimiter.go internal/common/tlsutils.go internal/common/transfer.go internal/common/transferschecker.go internal/common/edi_transfer_cap_test.go
go test -race -tags "edi,$SFTPGO_BUILD_TAGS" internal/sftpd/handler.go internal/sftpd/lister.go internal/sftpd/scp.go internal/sftpd/server.go internal/sftpd/sftpd.go internal/sftpd/ssh_cmd.go internal/sftpd/transfer.go internal/sftpd/edi_preauth_test.go internal/sftpd/edi_transfer_test.go
go test -race -tags "edi,$SFTPGO_BUILD_TAGS" internal/config/edi_limits_test.go
