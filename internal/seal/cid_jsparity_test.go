package seal

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCIDJSParity runs the JS-side CID parity check (parity/parity_check.mjs)
// against the shared parity/golden.json — the same fixtures the Go-side
// TestParityGolden checks. Green on both ⇒ public/seal-cid.mjs (the editor's
// module) and internal/seal.SealJSONLD compute byte-identical CIDs. Skipped if
// `node` is unavailable so CI without a Node toolchain still passes. Mirrors the
// pedersen_jsparity_test.go idiom.
func TestCIDJSParity(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed; skipping JS CID parity test")
	}

	root := sealRepoRoot(t)
	check := filepath.Join(root, "parity", "parity_check.mjs")
	if _, err := os.Stat(check); err != nil {
		t.Fatalf("parity/parity_check.mjs missing: %v", err)
	}

	cmd := exec.Command("node", "parity/parity_check.mjs")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("JS CID parity failed:\n%s\n%v", out, err)
	}
	t.Logf("%s", out)
}

func sealRepoRoot(t *testing.T) string {
	t.Helper()
	// See note in prover/pedersen_jsparity_test.go: skip the Go-side node-exec
	// parity under Bazel (covered by the hermetic //public:*_test targets).
	if os.Getenv("TEST_SRCDIR") != "" {
		t.Skip("repo-tree parity test — runs under `go test`; JS-side parity covered by //public:*_test under Bazel")
	}
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find project root (no go.mod ancestor)")
		}
		dir = parent
	}
}
