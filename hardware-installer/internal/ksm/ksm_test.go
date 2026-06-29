package ksm

import (
	"context"
	"path/filepath"
	"testing"
)

func TestConfigureIdempotent(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "ksmtuned.conf")
	params := Params{ConfigPath: configPath, Systemctl: "/usr/bin/true"}

	res1, err := Configure(context.Background(), params, ConfigureRequest{Enabled: true}, nil)
	if err != nil {
		t.Fatalf("Configure first call error = %v", err)
	}
	if !res1.Changed {
		t.Fatal("expected first call changed=true")
	}

	res2, err := Configure(context.Background(), params, ConfigureRequest{Enabled: true}, nil)
	if err != nil {
		t.Fatalf("Configure second call error = %v", err)
	}
	if res2.Changed {
		t.Fatal("expected second call changed=false")
	}
}
