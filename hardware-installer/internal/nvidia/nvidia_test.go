package nvidia

import "testing"

func TestDetectHeadersPackage(t *testing.T) {
	t.Parallel()

	pkg := detectHeadersPackage()
	if pkg == "" {
		t.Fatal("headers package should not be empty")
	}
}
