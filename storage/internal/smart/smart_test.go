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

// smartctl signals findings (e.g. an attribute that was once below threshold)
// with a non-zero exit code while still emitting a full JSON document. Poll must
// parse that JSON rather than discarding it as an error.
func TestPollParsesJSONDespiteWarningExitCode(t *testing.T) {
	const body = `{"smart_status":{"passed":true},"temperature":{"current":51},` +
		`"ata_smart_attributes":{"table":[{"name":"Power_On_Hours","raw":{"value":12345}}]}}`
	m := &storageexec.MockExec{Errs: map[string]error{"smartctl": storageexec.ErrExit}, Results: map[string]*storageexec.Result{
		"smartctl": {Stdout: []byte(body), ExitCode: 32},
	}}
	res, err := smart.Poll(context.Background(), m, []string{"/dev/sdd"})
	if err != nil {
		t.Fatalf("poll should not fail whole call: %v", err)
	}
	if len(res.Disks) != 1 {
		t.Fatalf("expected 1 disk, got %+v", res)
	}
	d := res.Disks[0]
	if d.Status != "passed" {
		t.Fatalf("expected passed despite exit 32, got %q (err=%q)", d.Status, d.Error)
	}
	if d.Temperature != 51 {
		t.Fatalf("expected temp 51, got %v", d.Temperature)
	}
	if d.Attributes["Power_On_Hours"] != 12345 {
		t.Fatalf("expected Power_On_Hours 12345, got %v", d.Attributes)
	}
}

// When smartctl emits no usable JSON and the device is not merely unsupported,
// the disk is reported as errored without aborting the whole poll.
func TestPollReportsErrorWhenNoJSON(t *testing.T) {
	m := &storageexec.MockExec{Errs: map[string]error{"smartctl": storageexec.ErrExit}, Results: map[string]*storageexec.Result{
		"smartctl": {Stderr: []byte("cannot open device"), ExitCode: 2},
	}}
	res, err := smart.Poll(context.Background(), m, []string{"/dev/sdz"})
	if err != nil {
		t.Fatalf("poll should not fail whole call: %v", err)
	}
	if len(res.Disks) != 1 || res.Disks[0].Status != "error" {
		t.Fatalf("expected error status, got %+v", res)
	}
}
