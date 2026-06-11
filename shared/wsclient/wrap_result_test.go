package wsclient

import (
	"encoding/json"
	"testing"
)

func TestWrapJobResult_PayloadObject(t *testing.T) {
	out := wrapJobResult("job-1", []byte(`{"vms":[{"vmid":100}]}`))
	var w map[string]any
	if err := json.Unmarshal(out, &w); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if w["type"] != "result" || w["jobId"] != "job-1" {
		t.Fatalf("bad wrapper: %v", w)
	}
	payload, ok := w["payload"].(map[string]any)
	if !ok || payload["vms"] == nil {
		t.Fatalf("payload not preserved: %v", w)
	}
	if _, hasErr := w["error"]; hasErr {
		t.Fatalf("unexpected error field: %v", w)
	}
}

func TestWrapJobResult_ErrorBody(t *testing.T) {
	out := wrapJobResult("job-2", []byte(`{"error":"UNSUPPORTED: vm.bogus"}`))
	var w map[string]any
	if err := json.Unmarshal(out, &w); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if w["error"] != "UNSUPPORTED: vm.bogus" {
		t.Fatalf("error not lifted: %v", w)
	}
	if w["jobId"] != "job-2" {
		t.Fatalf("jobId missing: %v", w)
	}
}

func TestWrapJobResult_NonJSON(t *testing.T) {
	out := wrapJobResult("job-3", []byte("plain text"))
	var w map[string]any
	if err := json.Unmarshal(out, &w); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if w["payload"] != "plain text" {
		t.Fatalf("non-JSON payload not stringified: %v", w)
	}
}
