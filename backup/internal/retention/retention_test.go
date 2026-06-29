package retention_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pmx-cloud/agents/backup/internal/retention"
)

func TestParseArchiveFileName(t *testing.T) {
	t.Parallel()

	parsed, ok := retention.ParseArchiveFileName("vzdump-qemu-101-2026_02_29-23_59_59.vma.zst")
	if ok {
		t.Fatal("expected invalid leap-day timestamp parsing to fail")
	}

	parsed, ok = retention.ParseArchiveFileName("vzdump-qemu-101-2024_02_29-23_59_59.vma.zst")
	if !ok {
		t.Fatal("expected valid archive filename")
	}
	if parsed.VMID != "101" {
		t.Fatalf("vmid = %q, want 101", parsed.VMID)
	}
}

func TestComputeKeepSet_DailyWeeklyMonthlyBoundaries(t *testing.T) {
	t.Parallel()

	mustTs := func(v string) time.Time {
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil {
			t.Fatalf("parse time %q: %v", v, err)
		}
		return ts
	}

	archives := []retention.Archive{
		{Path: "/r/a1", Timestamp: mustTs("2026-03-31T23:59:00Z")}, // end-of-month
		{Path: "/r/a2", Timestamp: mustTs("2026-03-30T12:00:00Z")},
		{Path: "/r/a3", Timestamp: mustTs("2026-03-24T12:00:00Z")}, // previous ISO week
		{Path: "/r/a4", Timestamp: mustTs("2026-02-28T23:59:00Z")}, // previous month
		{Path: "/r/a5", Timestamp: mustTs("2024-02-29T08:00:00Z")}, // leap year
	}

	kept := retention.ComputeKeepSet(archives, retention.Policy{KeepDailies: 2, KeepWeeklies: 2, KeepMonthlies: 2})

	if _, ok := kept["/r/a1"]; !ok {
		t.Fatal("latest backup should be kept")
	}
	if _, ok := kept["/r/a4"]; !ok {
		t.Fatal("month boundary archive should be kept by monthlies")
	}
	if len(kept) < 3 {
		t.Fatalf("expected at least 3 archives kept, got %d", len(kept))
	}
}

func TestApply_DryRunAndDelete(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	files := []string{
		"vzdump-qemu-101-2026_05_03-10_00_00.vma.zst",
		"vzdump-qemu-101-2026_05_02-10_00_00.vma.zst",
		"vzdump-qemu-101-2026_05_01-10_00_00.vma.zst",
	}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o644); err != nil {
			t.Fatalf("write %q: %v", name, err)
		}
	}

	dry, err := retention.Apply(retention.ApplyParams{
		ArchiveRoot:  root,
		ArchiveRoots: []string{root},
		Policy: retention.Policy{
			KeepDailies:   1,
			KeepWeeklies:  0,
			KeepMonthlies: 0,
		},
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry-run Apply() error = %v", err)
	}
	if got, want := len(dry.WouldDelete), 2; got != want {
		t.Fatalf("dry-run would_delete len = %d, want %d", got, want)
	}

	live, err := retention.Apply(retention.ApplyParams{
		ArchiveRoot:  root,
		ArchiveRoots: []string{root},
		Policy: retention.Policy{
			KeepDailies:   1,
			KeepWeeklies:  0,
			KeepMonthlies: 0,
		},
		DryRun: false,
	})
	if err != nil {
		t.Fatalf("live Apply() error = %v", err)
	}
	if len(live.Deleted) == 0 {
		t.Fatal("expected deleted archives")
	}
}
