//go:build !linux

package communityscript

import (
	"fmt"
	"io"
	"os"
)

// Non-Linux development fallback: create an unlinked temp file.
func createSealedScriptMemfd(script []byte) (int, *os.File, error) {
	tmp, err := os.CreateTemp("", "pmx-community-script-*")
	if err != nil {
		return -1, nil, fmt.Errorf("community-script: create temp script file failed: %w", err)
	}
	if _, err := tmp.Write(script); err != nil {
		tmp.Close()
		return -1, nil, fmt.Errorf("community-script: write temp script file failed: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		tmp.Close()
		return -1, nil, fmt.Errorf("community-script: rewind temp script file failed: %w", err)
	}
	_ = os.Remove(tmp.Name())
	return int(tmp.Fd()), tmp, nil
}

func closeMemfd(_ int, file *os.File) {
	if file != nil {
		_ = file.Close()
	}
}
