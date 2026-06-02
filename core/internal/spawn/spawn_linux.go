//go:build linux

package spawn

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// createSealedMemfd creates an anonymous memory file, writes data into it, then
// seals it against any further writes. Returns the file descriptor number.
//
// Seals applied: F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL.
// After sealing, the fd is immutable — even the spawning process cannot alter it.
func createSealedMemfd(data []byte) (int, error) {
	fd, err := unix.MemfdCreate("pmx-envelope", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return -1, fmt.Errorf("memfd_create: %w", err)
	}

	// Write the envelope bytes.
	n, err := unix.Write(fd, data)
	if err != nil || n != len(data) {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("write memfd: wrote %d/%d: %v", n, len(data), err)
	}

	// Seek back to 0 so the child reads from the start.
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("seek memfd: %w", err)
	}

	// Seal against any modification.
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("seal memfd: %w", err)
	}

	return fd, nil
}

// closeFd closes a file descriptor.
func closeFd(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}
