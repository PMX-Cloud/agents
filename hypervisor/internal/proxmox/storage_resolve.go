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

	var best string
	var bestAvail int64 = -1
	for _, s := range storages {
		if s.Active != 1 || !strings.Contains(s.Content, contentType) {
			continue
		}
		if s.Storage == requested {
			return requested
		}
		if s.Avail > bestAvail {
			best = s.Storage
			bestAvail = s.Avail
		}
	}

	if best == "" {
		return requested
	}
	return best
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
