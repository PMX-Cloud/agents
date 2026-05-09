# pmx-cloud-agent

Go agent installed on customer Proxmox/Debian hosts.

## Production Build

Requires Go `1.26.3` or newer. The module intentionally uses this floor because the production vulnerability scan depends on fixes present in Go `1.26.3`.

Build release binaries and checksums from the repository root:

```bash
./agent/scripts/build-release.sh
```

Defaults:

- Version: `0.1.0`
- Output: `agent/dist/`
- Targets: `linux/amd64`, `linux/arm64`

Override release metadata when publishing:

```bash
VERSION=0.1.0 COMMIT="$(git rev-parse --short HEAD)" ./agent/scripts/build-release.sh
```

The build script runs:

- `go mod verify`
- `go test ./...`
- `go build -trimpath` with injected version, commit, and build date
- SHA-256 checksum generation for every binary

## Install On A Host

Use the infra installer with a verified local binary:

```bash
sudo ./Infra/scripts/install-agent.sh \
  --token=pmx_xxx \
  --server-url=wss://ws.pmxcloud.cloud/ws/agent \
  --binary-path=./agent/dist/pmx-cloud-agent-0.1.0-linux-amd64
```

Or install from a release URL with a required checksum:

```bash
sudo ./Infra/scripts/install-agent.sh \
  --token=pmx_xxx \
  --server-url=wss://ws.pmxcloud.cloud/ws/agent \
  --binary-url=https://releases.pmxcloud.cloud/agent/0.1.0/pmx-cloud-agent-0.1.0-linux-amd64 \
  --binary-sha256=<expected_sha256>
```

The installer writes `/etc/pmx-cloud/agent.conf`, renders a systemd unit with the selected data directory, runs `pmx-cloud-agent --preflight`, enables the service, starts it unless `--no-start` is set, and verifies the service is active.

## Local Verification

```bash
cd agent
go mod verify
go test ./...
go build ./...
```

Validate an installed config without opening a WebSocket:

```bash
pmx-cloud-agent --preflight --config /etc/pmx-cloud/agent.conf
```
