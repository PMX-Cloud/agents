// Package nvme implements nvme.controller.add.
package nvme

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/pmx-cloud/agents/storage/internal/storageexec"
)

// ControllerParams controls namespace creation + attachment.
type ControllerParams struct {
	Controller  string `json:"controller"`
	SizeBlocks  int64  `json:"size_blocks"`
	BlockSize   int    `json:"block_size"`
	NamespaceID int    `json:"namespace_id"`
}

// ControllerAdd performs nvme list -> create-ns -> attach-ns.
func ControllerAdd(ctx context.Context, ex storageexec.Interface, p ControllerParams) error {
	if !strings.HasPrefix(p.Controller, "/dev/nvme") || strings.Contains(p.Controller, "..") {
		return fmt.Errorf("nvme.controller.add: invalid controller path")
	}
	if p.SizeBlocks <= 0 {
		return fmt.Errorf("nvme.controller.add: size_blocks must be > 0")
	}
	if p.BlockSize <= 0 {
		p.BlockSize = 4096
	}
	if p.NamespaceID <= 0 {
		p.NamespaceID = 1
	}

	if _, err := ex.Nvme(ctx, "list", "-o", "json"); err != nil {
		return fmt.Errorf("nvme.controller.add list: %w", err)
	}
	if _, err := ex.Nvme(ctx,
		"create-ns", p.Controller,
		"--nsze", strconv.FormatInt(p.SizeBlocks, 10),
		"--ncap", strconv.FormatInt(p.SizeBlocks, 10),
		"--block-size", strconv.Itoa(p.BlockSize),
	); err != nil {
		return fmt.Errorf("nvme.controller.add create-ns: %w", err)
	}
	if _, err := ex.Nvme(ctx,
		"attach-ns", p.Controller,
		"--namespace-id", strconv.Itoa(p.NamespaceID),
		"--controllers", "0",
	); err != nil {
		return fmt.Errorf("nvme.controller.add attach-ns: %w", err)
	}
	return nil
}
