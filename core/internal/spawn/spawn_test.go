package spawn_test

import (
	"testing"

	"github.com/pmx-cloud/agents/core/internal/spawn"
)

func TestInstantiateTemplate(t *testing.T) {
	cases := []struct {
		template string
		jobID    string
		want     string
	}{
		{"pmx-hardware-installer@.service", "abc123", "pmx-hardware-installer@abc123.service"},
		{"pmx-console-broker@.service", "job-99", "pmx-console-broker@job-99.service"},
		{"pmx-updater@.service", "upd-01", "pmx-updater@upd-01.service"},
	}
	for _, tc := range cases {
		got := spawn.InstantiateTemplate(tc.template, tc.jobID)
		if got != tc.want {
			t.Errorf("InstantiateTemplate(%q, %q) = %q, want %q", tc.template, tc.jobID, got, tc.want)
		}
	}
}

func TestTemplateToBinary(t *testing.T) {
	cases := []struct {
		template string
		want     string
	}{
		{"pmx-hardware-installer@.service", "/usr/local/bin/pmx-hardware-installer"},
		{"pmx-updater@.service", "/usr/local/bin/pmx-updater"},
	}
	for _, tc := range cases {
		got := spawn.TemplateToBinary(tc.template)
		if got != tc.want {
			t.Errorf("TemplateToBinary(%q) = %q, want %q", tc.template, got, tc.want)
		}
	}
}
