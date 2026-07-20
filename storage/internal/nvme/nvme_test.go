package nvme_test

import (
	"context"
	"testing"

	"github.com/pmx-cloud/agents/storage/internal/nvme"
	"github.com/pmx-cloud/agents/storage/internal/storageexec"
)

func TestControllerAddListsCreatesAndAttachesNamespace(t *testing.T) {
	m := &storageexec.MockExec{Results: map[string]*storageexec.Result{
		"nvme": {Stdout: []byte(`{"Devices":[]}`), ExitCode: 0},
	}}
	err := nvme.ControllerAdd(context.Background(), m, nvme.ControllerParams{Controller: "/dev/nvme0", SizeBlocks: 1024, BlockSize: 4096, NamespaceID: 1})
	if err != nil {
		t.Fatalf("controller add: %v", err)
	}
	if len(m.Calls) != 3 {
		t.Fatalf("expected list/create-ns/attach-ns, got %v", m.Calls)
	}
}
