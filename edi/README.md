# EDI maintenance profile

This fork starts from upstream SFTPGo 2.7.6, commit
`62ae9ba3957e9ed52b44a4f885e805e2d7b35972`. The upstream module path and AGPL license
remain unchanged. The S3 SFTP writer checks the authenticated maximum file extent
before writing, cancels refused transfers, and retains received-packet accounting.
Upload PUT, multipart initiation and multipart completion each use one SDK attempt.
An ambiguous successful write is therefore not automatically repeated to create another
version or upload. Part retries retain the same upload ID, part number and bytes;
read and credential retries keep their configured behavior. Copy/rename paths are unchanged.

`edi/build-inputs.env` owns the compiler and slim feature profile. Build a checked-out
or verified archive revision with `edi/build.sh /empty/runtime FULL_COMMIT_SHA`.
Run `edi/test.sh` for focused race, upload-retry and optional-S3 compile guards. Consumers must verify
their source revision/archive before invoking the recipe; the supplied revision and
generated binary hash are provenance for accidental mix-ups, not a signature.

Required runtime features are SFTP, S3, PostgreSQL, admin REST and metrics. GCS, Azure,
Bolt, MySQL, SQLite and portable mode are omitted. Optional bundle, AWS-container and
Unix-crypt features are not enabled. Dependency build options follow the upstream
release profile; transitive cloud packages may remain. The runtime includes only the
two required SMTP email templates and licensing/provenance files, without browser assets.

`Dockerfile.edi` uses the same recipe for Linux arm64 and runs as UID/GID 1000.
Supply your own `/etc/sftpgo/sftpgo.json`, TLS and SSH keys; PostgreSQL is required.
Keep `/var/lib/sftpgo`, `/tmp` and any configured staging directory writable when
using a read-only root filesystem. Both `serve` and `initprovider` remain available.
Disable browser UIs, FTP/WebDAV listeners and SSH commands in deployment configuration
while preserving admin REST. These runtime restrictions are not compile-time removals.

The sole active workflow is manual `EDI slim SFTPGo`; inherited upstream release and
CodeQL workflows are disabled in this fork. It publishes
`ghcr.io/bettiah/sftpgo:sha-FULL_COMMIT_SHA` through the workflow token. Consumers pin
the resulting digest after pulling and functionally qualifying that exact image.
An image publication is not a deployment. No additional architectures are qualified.

Retire the extent patch when an upstream release passes the same sparse-write,
transfer-cancellation and accounting guards. The extent patch alone does not provide aggregate
capacity enforcement or writer settlement. One attempt may commit while returning an
error; a lost initiation response can leave one unknown-ID MPU. Transient upload errors
previously hidden by retries become visible to clients. Use a correctly region-addressed
endpoint without redirects: the SDK attempt limit does not replace HTTP redirect handling
or lower transport recovery before a request is sent. It is not a universal HTTP-send bound.
Local SDK/native qualification does not replace exact Linux-artifact and real-AWS qualification.

Disk-backed staging write failures fail the whole download, including a transient
failure followed by a successful retry: the failure flag stays set. The pipe wrapper
prevents holes, truncation and zero-length "successful" downloads by converting
pipeat's ambiguous write EOF to a staging error and rejecting subsequent reads.
Uploads and downloads return `SSH_FX_FAILURE`. The wrapper logs once at Error per
failed pipe and increments the unlabelled `sftpgo_staging_errors_total` once.
Pipeat discards the errno, so this counts staging failures, not specifically ENOSPC.
Normal reader/writer closure is excluded.
An EOF short of the highest written offset also fails the pipe and increments the same
counter, detecting staging read errors hidden by pipeat after a clean download close.
A raw staging read error while the writer is open also fails the pipe and increments
`sftpgo_staging_errors_total`; negative or overflowing read offsets are rejected without
failing the pipe or counting a staging error. Upload write offsets are client-chosen and
have no such guard: set `max_upload_file_size`, which refuses out-of-range writes before
they reach the staging file, or they count as staging errors.

SSH external-auth transport errors, timeouts, non-200 responses, program failures,
invalid JSON and user save/validation failures after acceptance no longer score against
the client IP. This is unconditional and SSH-only; `200 {}` still rejects and scores.
Client-forcible 400s from over-length fields and hook saturation during a flood now
produce unscored hook load; the per-source rate limiter remains the brake. Backend
faults disguised as `200 {}` (including custody-release faults) still score. Post-KEX
abandonment remains unscored; a hook hang crossing the handshake deadline can still
score `NoLoginTried`. Both residual scoring cases are inert at `score_no_auth: 0`;
N1c is deferred to the release that considers raising it. SSH `max_sessions` refusals
after successful credential checks do not score for password, keyboard-interactive
or public-key auth; because the cap precedes the login-method, 2FA and address
filters, valid credentials those filters would refuse also get an unscored session
refusal while the user is at its cap.

`sftpd.handshake_timeout` is the SSH login grace period in seconds (default 120;
0 uses 120; negatives and 1–9 fail startup). It covers version exchange, KEX and
authentication, including hook latency, after the PROXY header's separate 10-second
bound. A running hook still waits for its own timeout even if the network deadline
expires; keep hook timeouts shorter than this grace period. Authentication clears the
deadline; `idle_timeout` then governs. Override with
`SFTPGO_SFTPD__HANDSHAKE_TIMEOUT`.

`common.max_total_transfers` defaults to 0 (off; negative values also disable it),
overridden by `SFTPGO_COMMON__MAX_TOTAL_TRANSFERS`. SFTP OPEN atomically reserves a slot
against active uploads/downloads plus pending opens until the active transfer is added
or OPEN fails; CLOSE frees the active slot. Other protocols' active transfers count,
but SCP, SSH commands, FTP, WebDAV and httpd transfers are never refused by
`max_total_transfers`. The hard bound requires `sftpd.enabled_ssh_commands: []`,
FTP/WebDAV ports 0 and httpd user file endpoints disabled. Existing connection/per-user
caps still apply. Under the same reservation, SFTP OPEN also refuses once the user's
active plus pending transfers on this process reach the user's `max_sessions` (0 is
unlimited), checked before `max_total_transfers` and against the session's login-time
value; other protocols are not refused by it and the same hard-bound preconditions apply.
New-cap refusal returns `SSH_FX_FAILURE` on OPEN without a defender
event; the session remains usable. `common.max_total_transfers`
does not participate in connection admission. A per-pod download staging disk bound
based on 5 GiB per slot assumes hosted outbound objects are at most 5 GiB; uploads'
extent cap alone does not establish that precondition.

`sftpgo_ssh_preauth_connections` counts accepted SSH connections after admission and
before authentication completes, excluding the PROXY header wait, and is released on
success, failure, deadline, close or panic. `sftpgo_capacity_refusals_total{limit}`
counts capacity refusals only, with `limit` equal to `max_total_connections`,
`max_per_host_connections`, `max_total_transfers` or `max_sessions`; safelisted overruns
are excluded. All four `limit` series are exported at 0 from startup.
There are no IP, username, path or stage labels. The existing shared connection limit
also applies to HTTP admin requests, so `limit="max_total_connections"` includes their
refusals. An SSH pre-auth flood can still impede admin REST under that shared limit.

## Neutral SSH identification

Set `common.server_version` to `"neutral"` (environment:
`SFTPGO_COMMON__SERVER_VERSION=neutral`) so clients see `SSH-2.0-EDI`: hosted
clients must not see the engine name. Existing settings retain their behavior.
The shared setting also neutralizes other users of the public server-version helper.
Activation requires restarting `serve`; SIGHUP does not reload this setting.

Neutral identification does not neutralize operator-supplied banners or hook-supplied
prompts. Leave `sftpd.login_banner_file` empty or supply neutral text, and ensure
keyboard-interactive hooks return neutral instructions/questions. Enabled SSH
commands retain their names and responses; the hosted profile disables them with
`sftpd.enabled_ssh_commands: []`. Local/SFTP-backend atomic-upload temporary files
retain `.sftpgo-upload.*` names; these are not used by the hosted S3 profile with
`common.upload_mode: 0`. Behavioural fingerprints, including algorithm order,
SFTP behaviour and quota wording, remain.

## RDS IAM database authentication

`data_provider.aws_iam_auth` (default `false`; `SFTPGO_DATA_PROVIDER__AWS_IAM_AUTH`) makes the
PostgreSQL provider authenticate with an RDS IAM auth token instead of a password. The AWS SDK
configuration is loaded once at provider start; every physical connection then builds a fresh
token for its `host:port` and user, from the SDK credentials cache, in pgx's `BeforeConnect`
(the existing host randomisation is kept). `data_provider.aws_iam_region`
(`SFTPGO_DATA_PROVIDER__AWS_IAM_REGION`) sets the token region; empty uses the SDK chain, such
as `AWS_REGION`. Credentials come from the SDK default chain (IRSA web identity in EKS). Both
`initprovider` and `serve` use it.

Startup refuses, before any connection or token build: a driver other than `postgresql`
(CockroachDB included); `data_provider.password`; `PGPASSWORD`, `PGPASSFILE`, `PGSERVICE` or
`PGSERVICEFILE` present in the environment, even empty; a connection-string key outside
`host port dbname user sslmode connect_timeout sslrootcert sslcert sslkey sslsni
target_session_attrs default_query_exec_mode`; and, on the parsed configuration, any password
(which also catches a default `~/.pgpass` entry or a service file), more than one host or any
fallback, TLS other than verify-full, and no region. The generated connection string has no
password key, and IAM mode never logs the connection string; a parse error's quoted string is
replaced by `[redacted]`.

The credential client is bounded, because the SDK cache runs a shared refresh under a context
without deadline and the default HTTP client has no response timeout: connect and TLS
handshake 2 s, response headers 3 s, each request 4 s, at most 2 attempts. A refresh against
an endpoint that accepts the connection and never answers therefore ends, and the next
connect after recovery starts a new one without a restart. Each connect waits at most 10 s in
the hook, which pgx runs before the DSN's `connect_timeout` applies; a caller's cancellation
also ends its wait.

Failure signal: every failed token build logs one Error line starting
`iam auth: token build failed` (class `credentials`, `signer`, `timeout` or `canceled`, plus an
AWS error code when one exists), and every other failed IAM-mode connect logs one Error line
starting `iam auth: connect failed` (class `auth`, `server`, `tls`, `timeout`, `canceled`,
`network` or `other`, plus the SQLSTATE when one exists). A failed build is not also logged as a
connect failure. Both lines carry non-secret counters (`builds`, `build_failures`,
`connect_attempts`, `connects`, `connect_failures`) and the expiry of the credentials last used.
The first success after failures logs one Info line starting `iam auth recovered:`. Lines
carry no token, key, raw SDK error or connection string. There is no new Prometheus series,
and `/healthz` is unchanged: it does not check the database.

The connection lifetime stays 240 s and idle time 120 s, so during an STS outage new connects
fail once the cached credentials can no longer be refreshed, and pooled connections end within
about one lifetime after that (expiry is lazy, on reuse). Local tests use stub credentials, a
local TLS PostgreSQL protocol fake and a local fake STS endpoint; they make no AWS call.
`edi/test.sh` runs the real-PostgreSQL leg only when `SFTPGO_EDI_PG_ADMIN_URL` names a local
superuser URL, and says so when it skips it. Real IAM login, IRSA refresh and the STS-cut
window need real AWS qualification.
