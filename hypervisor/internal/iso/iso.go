/*
Package iso implements vm.iso.upload.

Security constraint: the source URL must be in the backend-supplied allowlist
passed in the envelope params. It is never derived from a free-form param.
Any URL not in the allowlist is rejected before any network I/O.
*/
package iso

import (
	"context"
	"fmt"
	"strings"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

// Upload uploads an ISO from an allowlisted URL to a storage pool.
func Upload(ctx context.Context, px proxmox.ExecIface, params map[string]any) error {
	storage, err := proxmox.RequiredSafeToken(params, "storage")
	if err != nil {
		return err
	}

	// The URL must come from the backend-supplied allowlist in the envelope.
	allowlistRaw, _ := params["allowed_urls"].([]any)
	var allowlist []string
	for _, u := range allowlistRaw {
		if s, ok := u.(string); ok && strings.HasPrefix(s, "https://") {
			allowlist = append(allowlist, s)
		}
	}
	if len(allowlist) == 0 {
		return fmt.Errorf("iso.upload: allowed_urls list is empty or missing in envelope")
	}

	url := proxmox.StringParam(params, "url", "")
	if url == "" {
		return fmt.Errorf("iso.upload: url is required")
	}

	// Reject if not in allowlist — before ANY network fetch.
	found := false
	for _, allowed := range allowlist {
		if url == allowed {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("iso.upload: URL %q is not in the backend-supplied allowlist", url)
	}

	if _, err := px.Pvesm(ctx, "upload", storage, url); err != nil {
		return fmt.Errorf("iso.upload: %w", err)
	}
	return nil
}
