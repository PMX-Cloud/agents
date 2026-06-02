package upgrade

import (
	"context"
	"testing"
)

func TestRunCheckOnly(t *testing.T) {
	t.Parallel()

	res, err := Run(context.Background(), Params{
		AptGet:     "/usr/bin/true",
		PVEUpgrade: "/usr/bin/true",
	}, RunRequest{Mode: "check-only"}, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if res.RebootRequired {
		t.Fatal("expected check-only reboot_required=false")
	}
}

func TestRunRejectsInvalidMode(t *testing.T) {
	t.Parallel()

	_, err := Run(context.Background(), Params{AptGet: "/usr/bin/true", PVEUpgrade: "/usr/bin/true"}, RunRequest{Mode: "bad"}, nil)
	if err == nil {
		t.Fatal("expected invalid mode error")
	}
}
