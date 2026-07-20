package proxmox_test

import (
	"encoding/json"
	"testing"

	"github.com/pmx-cloud/agents/hypervisor/internal/proxmox"
)

func TestIntParam_NumericTypes(t *testing.T) {
	cases := []struct {
		name string
		val  any
		want int
	}{
		{"float64", float64(4096), 4096},
		{"int", int(2), 2},
		{"int64 (CBOR)", int64(2048), 2048},
		{"uint64 (CBOR)", uint64(8), 8},
		{"int32", int32(16), 16},
		{"json.Number", json.Number("512"), 512},
		{"missing", nil, 99},
	}
	for _, c := range cases {
		params := map[string]any{}
		if c.val != nil {
			params["k"] = c.val
		}
		if got := proxmox.IntParam(params, "k", 99); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}
