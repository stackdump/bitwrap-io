package prover

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadKeysOnlyProveSubprocess exercises the *exact* code path that
// surfaces the upstream gnark-crypto bug from issue #3 — a fresh process
// that loads cs/pk/vk for a BabyJubJub-using circuit, builds a witness,
// and proves, without ever calling `frontend.Compile` first. The
// process MUST first call `babyjubjub.GetEdwardsCurve()` to arm the
// `sync.Once`-guarded curve-params init, otherwise scalarMulHint
// computes a zero D, the in-circuit scalarMulFakeGLV check fires, and
// prove fails at "constraint not satisfied".
//
// In-process the lazy init is sticky: any earlier test that uses
// gnark's frontend or gnark-crypto's twistededwards Add path triggers
// the curve-params init, masking the bug. So we re-exec ourselves with
// `go test` against just this package, then run the inner body in a
// subprocess that does only the load+prove dance.
//
// Run: go test -run TestLoadKeysOnlyProveSubprocess -v ./prover
func TestLoadKeysOnlyProveSubprocess(t *testing.T) {
	if os.Getenv("BITWRAP_LOADKEYS_ONLY_INNER") == "1" {
		runLoadKeysOnlyProve(t)
		return
	}

	witnessPath := "/tmp/v3-witness-dump.json"
	if _, err := os.Stat(witnessPath); err != nil {
		t.Skipf("missing %s — run `cd e2e && npx playwright test --project=v3 -g dump` first", witnessPath)
	}

	for _, suffix := range []string{".cs", ".pk", ".vk"} {
		if _, err := os.Stat("/tmp/native-keys-voteCastHomomorphic_8" + suffix); err != nil {
			t.Skipf("missing /tmp/native-keys-voteCastHomomorphic_8%s — run `NATIVE_EXPORT_CIRCUIT=voteCastHomomorphic_8 go test -run TestNativeExportKeys ./prover` first", suffix)
		}
	}

	pkgDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "test", "-count=1", "-run", "TestLoadKeysOnlyProveSubprocess", "-v", pkgDir)
	cmd.Env = append(os.Environ(), "BITWRAP_LOADKEYS_ONLY_INNER=1")
	out, runErr := cmd.CombinedOutput()
	t.Log(string(out))
	if runErr != nil {
		t.Fatalf("subprocess: %v", runErr)
	}
	if !strings.Contains(string(out), "subprocess prove + verify OK") {
		t.Fatal("subprocess didn't reach the OK line")
	}
}
