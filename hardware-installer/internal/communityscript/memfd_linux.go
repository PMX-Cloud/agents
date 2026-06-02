//go:build linux

package communityscript

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func createSealedScriptMemfd(script []byte) (int, *os.File, error) {
	fd, err := unix.MemfdCreate("pmx-community-script", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return -1, nil, fmt.Errorf("community-script: memfd_create failed: %w", err)
	}
	file := os.NewFile(uintptr(fd), "pmx-community-script")
	if file == nil {
		unix.Close(fd)
		return -1, nil, fmt.Errorf("community-script: failed to wrap memfd")
	}
	if _, err := file.Write(script); err != nil {
		file.Close()
		return -1, nil, fmt.Errorf("community-script: write script memfd failed: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return -1, nil, fmt.Errorf("community-script: rewind script memfd failed: %w", err)
	}
	_, err = unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS,
		unix.F_SEAL_WRITE|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_SEAL)
	if err != nil {
		file.Close()
		return -1, nil, fmt.Errorf("community-script: seal memfd failed: %w", err)
	}
	return fd, file, nil
}

func closeMemfd(fd int, file *os.File) {
	if file != nil {
		_ = file.Close()
	} else if fd >= 0 {
		_ = unix.Close(fd)
	}
}
