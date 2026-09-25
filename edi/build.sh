#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/edi/build-inputs.env"
output=${1:?usage: edi/build.sh EMPTY_RUNTIME_DIRECTORY FULL_SOURCE_REVISION}
revision=${2:?full source revision is required for archive builds}
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || { echo 'expected full source revision' >&2; exit 2; }
mkdir -p "$output"
output=$(cd "$output" && pwd)
[[ -z "$(ls -A "$output")" ]] || { echo 'runtime directory must be empty' >&2; exit 2; }
export GOTOOLCHAIN=$SFTPGO_GO_VERSION GOFLAGS=-mod=readonly
[[ "$(go env GOVERSION)" == "$SFTPGO_GO_VERSION" ]] || { echo 'compiler mismatch' >&2; exit 1; }
cd "$root"
go build -buildvcs=false -trimpath -tags "$SFTPGO_BUILD_TAGS" \
  -ldflags "-s -w -X github.com/drakkan/sftpgo/v2/internal/version.commit=edi-$revision" \
  -o "$output/sftpgo" .
mkdir "$output/templates"
# Upstream SMTP initialization needs these even with SMTP and both browser UIs off.
cp -R templates/email "$output/templates/"
cp LICENSE NOTICE edi/build-inputs.env "$output/"
if command -v sha256sum >/dev/null; then
  digest=$(sha256sum "$output/sftpgo" | cut -d ' ' -f 1)
else
  digest=$(shasum -a 256 "$output/sftpgo" | cut -d ' ' -f 1)
fi
printf '{"schema":1,"repository":"ediapis/sftpgo","revision":"%s","go_version":"%s","build_tags":"%s","goos":"%s","goarch":"%s","binary_sha256":"%s"}\n' \
  "$revision" "$SFTPGO_GO_VERSION" "$SFTPGO_BUILD_TAGS" "$(go env GOOS)" "$(go env GOARCH)" "$digest" \
  > "$output/build-provenance.json"
go version -m "$output/sftpgo" > "$output/go-build-info.txt"
"$output/sftpgo" --version
cat "$output/build-provenance.json"
