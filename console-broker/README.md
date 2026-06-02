# pmx-console-broker

Per-session ephemeral agent that bridges VM consoles between the customer's
browser and the host. Today this agent **only supports Proxmox VE** — it
proxies the Proxmox VNC and SPICE WebSocket endpoints.

## Hypervisor support

| Host type | Console bridge | Status |
|---|---|---|
| Proxmox VE | Proxmox VNC / SPICE over WS | ✅ Shipping |
| libvirt / KVM (Debian/Ubuntu) | virsh / SPICE over libvirt-sock | ⏳ Deferred — lands with the libvirt VM provider |
| Plain Debian/Ubuntu (no hypervisor) | n/a | Not applicable |

The frontend renders an empty state on the Console tab for non-Proxmox nodes
("VM management requires a hypervisor"), so customers on a `generic-linux`
node never see a broken console action. Once the libvirt provider in
`agents/hypervisor/internal/providers/libvirt/` learns VM operations,
`pmx-console-broker` gains a parallel libvirt-backed code path.

## Architecture

Spawned on-demand by `pmx-core` when a console session is requested.
Connects outbound to the backend WebSocket gateway, authenticates via a
signed envelope, and proxies the host-side VNC/SPICE socket to the browser.
See `internal/` for the implementation.
