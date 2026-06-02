package smart_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/storage/internal/smart"
	"github.com/pmx-cloud/agents/storage/internal/storageexec"
)

func TestPollUnsupportedDiskDoesNotFailWholeCall(t *testing.T) {
	m := &storageexec.MockExec{Errs: map[string]error{"smartctl": storageexec.ErrExit}, Results: map[string]*storageexec.Result{
		"smartctl": {Stderr: []byte("SMART support is: Unavailable"), ExitCode: 4},
	}}
	res, err := smart.Poll(context.Background(), m, []string{"/dev/sdb"})
	if err != nil {
		t.Fatalf("poll should not fail whole call: %v", err)
	}
	if len(res.Disks) != 1 || res.Disks[0].Status != "unsupported" {
		t.Fatalf("expected unsupported result, got %+v", res)
	}
}
