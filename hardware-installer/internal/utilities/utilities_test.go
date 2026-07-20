package utilities

import (
	"context"
	"reflect"
	"testing"
)

func TestResolvePackages(t *testing.T) {
	t.Parallel()

	got, err := resolvePackages([]string{"htop", "iperf3", "htop"}, []string{"htop", "iperf3"})
	if err != nil {
		t.Fatalf("resolvePackages() error = %v", err)
	}
	want := []string{"htop", "iperf3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolvePackages() = %#v, want %#v", got, want)
	}
}

func TestResolvePackagesRejectsUnknown(t *testing.T) {
	t.Parallel()

	_, err := resolvePackages([]string{"curl"}, []string{"htop"})
	if err == nil {
		t.Fatal("expected allowlist error")
	}
}

func TestInstallWithTrueBinary(t *testing.T) {
	t.Parallel()

	res, err := Install(context.Background(), Params{
		AptGet:          "/usr/bin/true",
		AllowedPackages: []string{"htop", "iperf3"},
	}, InstallRequest{Packages: []string{"iperf3", "htop"}}, nil)
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if len(res.Installed) != 2 {
		t.Fatalf("unexpected installed list: %#v", res.Installed)
	}
}
