#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source edi/build-inputs.env
export GOTOOLCHAIN=$SFTPGO_GO_VERSION GOFLAGS=-mod=readonly
# Tests that initialize process globals must be tag-isolated from upstream suites.
# Run edi-tagged tests file-scoped via this script only; package-mode -tags edi contaminates globals.
# File-scoped: upstream package TestMain starts unrelated providers/listeners.
go test -race -tags "edi,$SFTPGO_BUILD_TAGS" internal/metric/edi_capacity_test.go
go test -race -tags "edi,$SFTPGO_BUILD_TAGS" internal/sftpd/transfer.go internal/sftpd/stored_extent_test.go
go test -race -tags "edi,nos3,$SFTPGO_BUILD_TAGS" internal/sftpd/transfer.go internal/sftpd/stored_extent_test.go
go test -race -tags "$SFTPGO_BUILD_TAGS" ./internal/vfs -run '^TestS3(Upload|Complete|Read|Credential)'
go test -race -tags "$SFTPGO_BUILD_TAGS" ./internal/vfs -run '^TestEDIStaging'
go test -race -tags "$SFTPGO_BUILD_TAGS" internal/common/actions.go internal/common/clientsmap.go internal/common/common.go internal/common/connection.go internal/common/dataretention.go internal/common/defender.go internal/common/defenderdb.go internal/common/defendermem.go internal/common/eventmanager.go internal/common/eventscheduler.go internal/common/httpauth.go internal/common/ratelimiter.go internal/common/tlsutils.go internal/common/transfer.go internal/common/transferschecker.go internal/common/edi_transfer_cap_test.go
go test -race -tags "edi,$SFTPGO_BUILD_TAGS" internal/sftpd/handler.go internal/sftpd/lister.go internal/sftpd/scp.go internal/sftpd/server.go internal/sftpd/sftpd.go internal/sftpd/ssh_cmd.go internal/sftpd/transfer.go internal/sftpd/edi_preauth_test.go internal/sftpd/edi_transfer_test.go internal/sftpd/edi_ident_test.go internal/sftpd/edi_ident_config_test.go
go test -race -tags "edi,$SFTPGO_BUILD_TAGS" internal/config/edi_limits_test.go
go test -race ./internal/version
go test -race -tags "edi,$SFTPGO_BUILD_TAGS" internal/config/edi_iam_config_test.go
# Web identity guard: the shared source, the S3 filesystem path and (below) the IAM auth path.
go test -race -tags "edi,$SFTPGO_BUILD_TAGS" internal/awscreds/webidentity.go internal/awscreds/edi_webidentity_test.go
go test -race -tags "$SFTPGO_BUILD_TAGS" ./internal/vfs -run '^TestEDIS3WebIdentityGuard$'
# RDS IAM auth: the package's non-test files for this profile plus the edi tests (go list -tags "$SFTPGO_BUILD_TAGS" ./internal/dataprovider).
iam_files=(
  actions.go admin.go apikey.go bolt_disabled.go cachedpassword.go cacheduser.go configs.go
  dataprovider.go eventrule.go group.go iamauth.go iplist.go memory.go mysql_disabled.go
  node.go pgsql.go quotaupdater.go role.go scheduler.go session.go share.go
  sqlcommon.go sqlite_disabled.go sqlqueries.go unixcrypt_disabled.go user.go
)
iam_files=("${iam_files[@]/#/internal/dataprovider/}")
go test -race -tags "edi,$SFTPGO_BUILD_TAGS" "${iam_files[@]}" internal/dataprovider/edi_iamauth_test.go internal/dataprovider/edi_iamauth_sts_test.go
# Real PostgreSQL leg: needs a local superuser URL; it creates and drops its own role and database.
if [[ -n "${SFTPGO_EDI_PG_ADMIN_URL:-}" ]]; then
  go test -race -tags "edi,$SFTPGO_BUILD_TAGS" "${iam_files[@]}" internal/dataprovider/edi_iamauth_test.go internal/dataprovider/edi_iamauth_pg_test.go -run '^TestEDIIAMLocalPostgres$'
else
  echo 'SKIPPED: RDS IAM local PostgreSQL leg (set SFTPGO_EDI_PG_ADMIN_URL)' >&2
fi
