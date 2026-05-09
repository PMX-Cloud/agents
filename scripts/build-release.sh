#!/usr/bin/env bash
#
# Build pmx-cloud-agent release binaries and SHA-256 checksum files.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${DIST_DIR:-${AGENT_DIR}/dist}"
VERSION="${VERSION:-0.1.0}"
COMMIT="${COMMIT:-$(git -C "$AGENT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

targets=(
  "linux/amd64"
  "linux/arm64"
)

mkdir -p "$DIST_DIR"

cd "$AGENT_DIR"
go mod verify
go test ./...

for target in "${targets[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  output="${DIST_DIR}/pmx-cloud-agent-${VERSION}-${goos}-${goarch}"

  echo "building ${output}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build \
    -trimpath \
    -ldflags="-s -w -buildid= -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" \
    -o "$output" \
    .

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$output" > "${output}.sha256"
  else
    shasum -a 256 "$output" > "${output}.sha256"
  fi
done

echo "release artifacts written to ${DIST_DIR}"
