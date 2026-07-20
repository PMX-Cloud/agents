// Package serial provides local unix-socket connectivity for Proxmox serial consoles.
package serial

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
)

func SocketPath(qemuRunDir string, vmid int) string {
	return filepath.Join(qemuRunDir, fmt.Sprintf("%d.serial0", vmid))
}

func Connect(ctx context.Context, qemuRunDir string, vmid int) (net.Conn, error) {
	sock := SocketPath(qemuRunDir, vmid)
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, fmt.Errorf("INTERFACE_UNAVAILABLE: serial socket %q: %w", sock, err)
	}
	return conn, nil
}
