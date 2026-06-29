package spawn_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/pmx-cloud/agents/shared/envelope"

	"github.com/pmx-cloud/agents/core/internal/spawn"
)

func makeEnvelope() *envelope.Envelope {
	return &envelope.Envelope{
		Version:  "pmx-agent-v1",
		JobID:    "test-job-001",
		Command:  "hardware.install",
		Audience: "pmx-hardware-installer",
	}
}

func TestSpawn_MissingTemplate(t *testing.T) {
	s := spawn.NewSpawner(slog.Default())
	err := s.Spawn(context.Background(), spawn.EphemeralRequest{
		Template: "",
		JobID:    "job-001",
		Envelope: makeEnvelope(),
	})
	if err == nil {
		t.Fatal("expected error for missing template")
	}
}

func TestSpawn_MissingJobID(t *testing.T) {
	s := spawn.NewSpawner(slog.Default())
	err := s.Spawn(context.Background(), spawn.EphemeralRequest{
		Template: "pmx-hardware-installer@.service",
		JobID:    "",
		Envelope: makeEnvelope(),
	})
	if err == nil {
		t.Fatal("expected error for missing job ID")
	}
}

func TestSpawn_MissingEnvelope(t *testing.T) {
	s := spawn.NewSpawner(slog.Default())
	err := s.Spawn(context.Background(), spawn.EphemeralRequest{
		Template: "pmx-hardware-installer@.service",
		JobID:    "job-001",
		Envelope: nil,
	})
	if err == nil {
		t.Fatal("expected error for nil envelope")
	}
}

func TestTemplateToBinary_AllTemplates(t *testing.T) {
	cases := []struct {
		template string
		want     string
	}{
		{"pmx-hardware-installer@.service", "/usr/local/bin/pmx-hardware-installer"},
		{"pmx-updater@.service", "/usr/local/bin/pmx-updater"},
		{"pmx-console-broker@.service", "/usr/local/bin/pmx-console-broker"},
	}
	for _, tc := range cases {
		got := spawn.TemplateToBinary(tc.template)
		if got != tc.want {
			t.Errorf("TemplateToBinary(%q) = %q, want %q", tc.template, got, tc.want)
		}
	}
}

func TestInstantiateTemplate_EdgeCases(t *testing.T) {
	cases := []struct {
		template, jobID, want string
	}{
		{"pmx-hardware-installer@.service", "abc-123", "pmx-hardware-installer@abc-123.service"},
		{"pmx-updater@.service", "upd-v2-001", "pmx-updater@upd-v2-001.service"},
	}
	for _, tc := range cases {
		got := spawn.InstantiateTemplate(tc.template, tc.jobID)
		if got != tc.want {
			t.Errorf("InstantiateTemplate(%q, %q) = %q, want %q", tc.template, tc.jobID, got, tc.want)
		}
	}
}

func TestNewSpawner_NilLogger(t *testing.T) {
	// Must not panic with a nil logger.
	s := spawn.NewSpawner(nil)
	if s == nil {
		t.Fatal("expected non-nil Spawner")
	}
}
