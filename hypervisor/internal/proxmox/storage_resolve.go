package proxmox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// nodeStorage mirrors the fields we consume from pvesh /nodes/<node>/storage.
type nodeStorage struct {
	Storage string `json:"storage"`
	Content string `json:"content"`
	Type    string `json:"type"`
	Active  int    `json:"active"`
	Enabled int    `json:"enabled"`
	Avail   int64  `json:"avail"`
}

// ResolveStorage returns a storage usable for the given content type
// ("images" for VM disks, "rootdir" for CT root filesystems).
//
// If the requested storage is active and supports the content type it is used
// as-is. Otherwise the active storage with that content type and the most
// free space wins — backends hardcode defaults like "local-lvm" that do not
// exist on every host, and failing a whole VM create over a label the tenant
// never chose helps nobody. Returns the requested name unchanged when the
// storage list cannot be read (qm/pct will then surface their own error).
func ResolveStorage(ctx context.Context, px ExecIface, requested, contentType string) string {
	node := pveNodeName()
	if node == "" {
		return requested
	}
	result, err := px.Pvesh(ctx, "get", "/nodes/"+node+"/storage", "--output-format", "json")
	if err != nil || result.ExitCode != 0 {
		return requested
	}

	var storages []nodeStorage
	if err := json.Unmarshal(result.Stdout, &storages); err != nil {
		return requested
	}

	// A CT root filesystem ("rootdir") on a "dir" storage is a .raw file attached
	// via a loop device (losetup), which fails under the agent; prefer block
	// storage (lvm/lvmthin/zfspool/…). Block storages are local and activate on
	// demand, so for rootdir we accept an *enabled* block even when the node's
	// storage status currently reports it inactive (active=0) — pct/qm activate
	// it during create. VM disks ("images") run fine on "dir" (plain raw file,
	// no loop) and keep the simple largest-active choice.
	preferBlock := contentType == "rootdir"

	var best, bestBlock string
	var bestAvail, bestBlockAvail int64 = -1, -1
	for _, s := range storages {
		if s.Enabled != 1 || !strings.Contains(s.Content, contentType) {
			continue
		}

		if preferBlock && isBlockStorage(s.Type) {
			if bestBlock == "" || s.Avail > bestBlockAvail {
				bestBlock = s.Storage
				bestBlockAvail = s.Avail
			}
			continue
		}

		// Non-block storage (and all VM-image selection): only trust storage the
		// node reports active, so we never pick a down network share.
		if s.Active != 1 {
			continue
		}
		if s.Storage == requested && !preferBlock {
			return requested
		}
		if s.Avail > bestAvail {
			best = s.Storage
			bestAvail = s.Avail
		}
	}

	if preferBlock && bestBlock != "" {
		return bestBlock
	}
	if best == "" {
		return requested
	}
	return best
}

// isBlockStorage reports whether a Proxmox storage type provisions native block
// volumes, so a CT rootfs needs no loop device (losetup).
func isBlockStorage(t string) bool {
	switch t {
	case "lvm", "lvmthin", "zfspool", "zfs", "rbd", "iscsi", "iscsidirect":
		return true
	default:
		return false
	}
}

// FormatDiskSpec renders a qm/pct volume allocation spec like "GB-250:32".
func FormatDiskSpec(storage string, sizeGb int) string {
	return fmt.Sprintf("%s:%d", storage, sizeGb)
}

// pveNodeName returns the PVE node name (short hostname).
func pveNodeName() string {
	hn, err := os.Hostname()
	if err != nil || hn == "" {
		return ""
	}
	if i := strings.IndexByte(hn, '.'); i > 0 {
		return hn[:i]
	}
	return hn
}
