# PMX-Cloud Agent Fleet

Host-side agent fleet for [PMX-Cloud](https://pmxcloud.cloud) — a self-hosted, multi-tenant
VPS hosting control plane. These agents are installed on customer Proxmox VE / Debian / Ubuntu
hosts and connect **outbound** over WebSocket to the PMX-Cloud backend's agent gateway. Each
agent has a focused capability set; signed CBOR envelopes dispatch jobs to per-agent handlers.

> This repository is a **read-only source mirror**, published per release from the PMX-Cloud
> monorepo. Open issues/PRs upstream. Released binaries (signed, with SBOMs) are served from
> `https://releases.pmxcloud.cloud`.

## The fleet

| Agent | Lang | Lifecycle | Purpose |
|---|---|---|---|
| `core` | Go | long-running | supervisor, job router (mandatory on every host) |
| `telemetry` | Go | long-running | metrics, logs, heartbeat (read-only) |
| `hypervisor` | Go | long-running | VM/CT/cluster ops via the provider abstraction |
| `storage` | Go | long-running | disks, ZFS, SMART, NVMe |
| `network` | Rust | long-running | VLAN, OVS, WireGuard, nftables |
| `security` | Go | long-running | hardening, CVE/cert audit, compliance |
| `backup` | Go | long-running (optional) | backup orchestration + sync |
| `console-broker` | Go | per-session ephemeral | console session bridging |
| `hardware-installer` | Go | one-shot ephemeral | driver + IOMMU operations |
| `updater` | Rust | one-shot ephemeral | self-update, OS patching, maintenance windows |
| `shared` / `shared-rust` | Go / Rust | library | wsclient, signed envelope, capability registry, audit |
| `example` | Go | template | reference scaffolding for a new agent (not deployed) |

## Build

Each agent is an independent module.

```sh
# Go agents (Go 1.26.3+)
cd core && go build ./... && go test ./...

# Rust agents
cd network && cargo build && cargo test

# Shared libraries + lint/test/gates
make all && make lint && make test && make gates
```

## Install

```sh
curl -fsSL https://releases.pmxcloud.cloud/install-core.sh | sudo bash
```

## Security

Releases are signed (Ed25519); the public key and per-binary `.sha256`/`.sig` sidecars are
published alongside each release. Report security issues privately to the PMX-Cloud team rather
than via public issues.
