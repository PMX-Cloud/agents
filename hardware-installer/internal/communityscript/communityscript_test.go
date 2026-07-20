package communityscript

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDecodeScript(t *testing.T) {
	t.Parallel()

	got, err := decodeScript(base64.StdEncoding.EncodeToString([]byte("echo ok")))
	if err != nil {
		t.Fatalf("decodeScript() error = %v", err)
	}
	if string(got) != "echo ok" {
		t.Fatalf("decodeScript() = %q, want %q", string(got), "echo ok")
	}
}

func TestNormalizeWritePaths(t *testing.T) {
	t.Parallel()

	paths, err := normalizeWritePaths([]string{"/tmp/work", "/var/tmp/a"}, []string{"/tmp", "/var/tmp"})
	if err != nil {
		t.Fatalf("normalizeWritePaths() error = %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}

	_, err = normalizeWritePaths([]string{"/etc"}, []string{"/tmp", "/var/tmp"})
	if err == nil {
		t.Fatal("expected root enforcement error")
	}
}

func TestLoadReleasePublicKeyAndVerifySignature(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "release.pub")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	loaded, err := loadReleasePublicKey(keyPath)
	if err != nil {
		t.Fatalf("loadReleasePublicKey() error = %v", err)
	}
	script := []byte("echo signed")
	sig := ed25519.Sign(priv, script)
	if !ed25519.Verify(loaded, script, sig) {
		t.Fatal("expected signature verification to pass")
	}

	decodedSig, err := decodeSignature(hex.EncodeToString(sig))
	if err != nil {
		t.Fatalf("decodeSignature() error = %v", err)
	}
	if !ed25519.Verify(loaded, script, decodedSig) {
		t.Fatal("decoded signature should verify")
	}
}

func TestBuildSystemdRunArgsPrivateNetwork(t *testing.T) {
	t.Parallel()

	args, err := buildSystemdRunArgs("/bin/bash", 0, []string{"/tmp/work"}, false, nil)
	if err != nil {
		t.Fatalf("buildSystemdRunArgs() error = %v", err)
	}
	joined := stringsJoin(args)
	if !contains(args, "--property=PrivateNetwork=true") {
		t.Fatalf("expected PrivateNetwork=true in args: %s", joined)
	}
	if containsPrefix(args, "--property=StandardInput=") {
		t.Fatalf("did not expect StandardInput fd binding in args: %s", joined)
	}
	if !contains(args, "/bin/bash") || !contains(args, "/proc/self/fd/3") {
		t.Fatalf("expected interpreter and proc fd path in args: %s", joined)
	}
}

func TestBuildSystemdRunArgsRequiresExplicitIPAllowlist(t *testing.T) {
	t.Parallel()

	if _, err := buildSystemdRunArgs("/bin/bash", 1, []string{"/tmp/work"}, true, nil); err == nil {
		t.Fatal("expected allowNetwork=true without allowlist to fail")
	}
}

func TestBuildExecTarget(t *testing.T) {
	t.Parallel()

	execPath, execArgs, err := buildExecTarget("/usr/bin/python3", 2)
	if err != nil {
		t.Fatalf("buildExecTarget() error = %v", err)
	}
	if execPath != "/usr/bin/python3" {
		t.Fatalf("buildExecTarget() path = %q", execPath)
	}
	want := []string{"/proc/self/fd/5"}
	if !reflect.DeepEqual(execArgs, want) {
		t.Fatalf("buildExecTarget() args = %v, want %v", execArgs, want)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if len(value) >= len(prefix) && value[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func stringsJoin(values []string) string {
	result := ""
	for index, value := range values {
		if index > 0 {
			result += " "
		}
		result += value
	}
	return result
}
