package prover

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestPedersenJSParity runs the JS-side parity check against the
// committed pedersen_vectors.json. Skipped if `node` is unavailable so
// CI without a Node toolchain still passes — the Go side covers
// correctness and the JS test guards drift when run.
func TestPedersenJSParity(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed; skipping JS pedersen parity test")
	}

	root := findRepoRoot(t)
	vectors := filepath.Join(root, "public", "pedersen_vectors.json")
	if _, err := os.Stat(vectors); err != nil {
		t.Fatalf("pedersen_vectors.json missing — regenerate with BITWRAP_EMIT_VECTORS=1 go test ./prover -run TestEmitParityVectors: %v", err)
	}

	cmd := exec.Command("node", "public/pedersen_parity_test.mjs")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("JS parity test failed:\n%s\n%v", out, err)
	}
	t.Logf("%s", out)
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
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
