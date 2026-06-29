package sftp

import "testing"

func TestResumeOffsetRejectsRemoteLargerThanLocal(t *testing.T) {
	t.Parallel()

	_, err := resumeOffset(10, 20)
	if err == nil {
		t.Fatal("expected oversized remote partial to be rejected")
	}
}

func TestResumeOffsetAllowsPartialRemote(t *testing.T) {
	t.Parallel()

	offset, err := resumeOffset(20, 10)
	if err != nil {
		t.Fatalf("resumeOffset() error = %v", err)
	}
	if offset != 10 {
		t.Fatalf("offset = %d, want 10", offset)
	}
}
