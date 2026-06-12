//go:build !js && !wasm

// This test runs on the *host* toolchain (not the wasm one) and shells
// out to `node` to load public/prover.wasm and verify that the v3
// circuits — voteCastHomomorphic_8 and tallyDecrypt_8 — are registered
// in circuitByName. A divergence between cmd/prover-wasm/main.go's
// switch and the JS-side dispatch surfaces as a test failure here
// before reaching a browser.

package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProverWasmCircuitsSmoke(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed; skipping wasm smoke test")
	}
	root := repoRoot(t)
	wasmPath := filepath.Join(root, "public", "prover.wasm")
	if _, err := os.Stat(wasmPath); err != nil {
		t.Skipf("public/prover.wasm not built yet (run `make wasm`): %v", err)
	}

	cmd := exec.Command("node", "public/prover_wasm_circuits_smoke.mjs")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("smoke test failed:\n%s\n%v", out, err)
	}
	if !strings.Contains(string(out), "All prover.wasm circuit dispatches OK") {
		t.Fatalf("smoke test output unexpected:\n%s", out)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// Skip the Go-side node+wasm smoke under Bazel (the repo tree isn't on
	// disk); it runs under `go test`. Hermetic wasm is built by //public:gen_prover_wasm.
	if os.Getenv("TEST_SRCDIR") != "" {
		t.Skip("repo-tree wasm smoke — runs under `go test`")
	}
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no go.mod ancestor)")
		}
		dir = parent
	}
}
