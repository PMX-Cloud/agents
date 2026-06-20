package spawn

import "testing"

func TestProfileForTemplateConsoleBroker(t *testing.T) {
	t.Parallel()

	p := profileForTemplate("pmx-console-broker@.service")
	// Root is required to connect() to the root-owned qemu serial socket.
	if p.User != "root" {
		t.Fatalf("user = %q, want root", p.User)
	}
	if p.ServiceType != "simple" {
		t.Fatalf("type = %q, want simple", p.ServiceType)
	}
	if p.DefaultRuntime != 14_400 {
		t.Fatalf("default runtime = %d, want 14400", p.DefaultRuntime)
	}
}

func TestProfileForTemplateFallback(t *testing.T) {
	t.Parallel()

	p := profileForTemplate("unknown-template@.service")
	if p.User != "root" || p.ServiceType != "oneshot" {
		t.Fatalf("fallback profile mismatch: %#v", p)
	}
}
