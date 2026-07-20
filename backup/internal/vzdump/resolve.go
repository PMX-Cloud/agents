package vzdump

import (
	"os"
	"path/filepath"
)

// trustedBinDirs are the directories a backup binary may be resolved from when
// the configured path is absent. Package var so tests can override it.
var trustedBinDirs = []string{
	"/usr/sbin",
	"/sbin",
	"/usr/bin",
	"/bin",
	"/usr/local/sbin",
	"/usr/local/bin",
}

// ResolveBinary returns the real on-host path for a backup binary. It prefers
// the configured/default path; if that file is absent (common on usr-merged
// Proxmox hosts where e.g. vzdump moved from /usr/sbin to /usr/bin), it searches
// the trusted bin dirs for the same basename. When nothing is found the
// configured path is returned unchanged so the eventual exec fails with a clear
// error. This removes the need for host-side symlinks.
func ResolveBinary(configured string) string {
	if isExecutableFile(configured) {
		return configured
	}
	base := filepath.Base(configured)
	for _, dir := range trustedBinDirs {
		candidate := filepath.Join(dir, base)
		if isExecutableFile(candidate) {
			return candidate
		}
	}
	return configured
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}
