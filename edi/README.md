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
transfer-cancellation and accounting guards. This patch does not provide aggregate
capacity enforcement or writer settlement. One attempt may commit while returning an
error; a lost initiation response can leave one unknown-ID MPU. Transient upload errors
previously hidden by retries become visible to clients. Use a correctly region-addressed
endpoint without redirects: the SDK attempt limit does not replace HTTP redirect handling
or lower transport recovery before a request is sent. It is not a universal HTTP-send bound.
Local SDK/native qualification does not replace exact Linux-artifact and real-AWS qualification.
