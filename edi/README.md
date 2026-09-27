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
caps still apply. New-cap refusal returns `SSH_FX_FAILURE` on OPEN without a defender
event; the session remains usable. This key
does not participate in connection admission. A per-pod download staging disk bound
based on 5 GiB per slot assumes hosted outbound objects are at most 5 GiB; uploads'
extent cap alone does not establish that precondition.

`sftpgo_ssh_preauth_connections` counts accepted SSH connections after admission and
before authentication completes, excluding the PROXY header wait, and is released on
success, failure, deadline, close or panic. `sftpgo_capacity_refusals_total{limit}`
counts capacity refusals only, with `limit` equal to `max_total_connections`,
`max_per_host_connections` or `max_total_transfers`; safelisted overruns are excluded.
There are no IP, username, path or stage labels. The existing shared connection limit
also applies to HTTP admin requests, so `limit="max_total_connections"` includes their
refusals. An SSH pre-auth flood can still impede admin REST under that shared limit.
