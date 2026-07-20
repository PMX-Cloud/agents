package auditd_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pmx-cloud/agents/security/internal/auditd"
)

func TestQueryFallbackBounded(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "pmx-security.audit.log")
	_ = os.WriteFile(logPath, []byte("a\n\nb\nc\n"), 0o600)
	lines, err := auditd.Query(context.Background(), auditd.QueryParams{AuditPath: logPath, MaxLines: 2, Key: "pmx", Since: "today"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d (%v)", len(lines), lines)
	}
}
