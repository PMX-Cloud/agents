package config_test

import (
	"strings"
	"testing"

	"github.com/pmx-cloud/agents/backup/internal/config"
)

func TestParse_ConfigDefaults(t *testing.T) {
	t.Parallel()

	raw := `
[backend]
url = "wss://api.pmxcloud.example/ws/agent/backup"

[identity]
cert = "/etc/pmx-cloud/pmx-backup/client.crt"
key = "/etc/pmx-cloud/pmx-backup/client.key"

[keyset]
path = "/etc/pmx-cloud/keyset.pub"

[storage]
archive_roots = ["/var/lib/vz/dump", "/mnt/backups", "/var/lib/vz/dump"]

[limits]
max_concurrent_jobs = 0
max_concurrent_syncs = 0
`

	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if got, want := cfg.VZDump.Binary, "/usr/sbin/vzdump"; got != want {
		t.Fatalf("vzdump.binary = %q, want %q", got, want)
	}
	if got, want := len(cfg.Storage.ArchiveRoots), 2; got != want {
		t.Fatalf("archive_roots len = %d, want %d", got, want)
	}
	if got, want := cfg.Limits.MaxConcurrentJobs, 2; got != want {
		t.Fatalf("max_concurrent_jobs = %d, want %d", got, want)
	}
	if got, want := cfg.Limits.MaxConcurrentSyncs, 4; got != want {
		t.Fatalf("max_concurrent_syncs = %d, want %d", got, want)
	}
}

func TestParse_RejectsMissingArchiveRoots(t *testing.T) {
	t.Parallel()

	raw := `
[backend]
url = "wss://api.pmxcloud.example/ws/agent/backup"

[identity]
cert = "/etc/pmx-cloud/pmx-backup/client.crt"
key = "/etc/pmx-cloud/pmx-backup/client.key"
`

	_, err := config.Parse([]byte(raw))
	if err == nil || !strings.Contains(err.Error(), "storage.archive_roots") {
		t.Fatalf("expected storage.archive_roots error, got %v", err)
	}
}

func TestParse_RejectsRelativeArchiveRoot(t *testing.T) {
	t.Parallel()

	raw := `
[backend]
url = "wss://api.pmxcloud.example/ws/agent/backup"

[identity]
cert = "/etc/pmx-cloud/pmx-backup/client.crt"
key = "/etc/pmx-cloud/pmx-backup/client.key"

[storage]
archive_roots = ["./relative"]
`

	_, err := config.Parse([]byte(raw))
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute-path error, got %v", err)
	}
}
