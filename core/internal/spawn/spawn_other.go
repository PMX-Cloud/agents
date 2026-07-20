//go:build !linux

package spawn

import "fmt"

// createSealedMemfd is not supported on non-Linux platforms.
// Returns an error so the caller can surface a clear message.
func createSealedMemfd(_ []byte) (int, error) {
	return -1, fmt.Errorf("memfd_create is not supported on this platform (Linux only)")
}

// closeFd is a no-op on non-Linux.
func closeFd(_ int) {}
