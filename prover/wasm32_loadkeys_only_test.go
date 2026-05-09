package prover

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadKeysOnlyProveSubprocess exercises the *exact* code path that
// surfaced gnark-crypto's missing initOnce.Do(initCurveParams) in
// twistededwards.PointExtended.Add (issue #3): a fresh process that
// loads cs/pk/vk for a BabyJubJub-using circuit, builds a witness,
// proves — without ever calling frontend.Compile or
// twistededwards.GetEdwardsCurve first.
//
// In-process the lazy init is sticky: any earlier test that uses
// gnark's frontend or gnark-crypto's twistededwards package triggers
// the curve-params init, masking the bug. So we re-exec ourselves with
// `go test` against this very test file, isolated from the rest of
// the suite.
//
// Pre-fix this subprocess fails at "constraint #2459 not satisfied"
// mid scalarMulFakeGLV. Post-fix it returns a valid Groth16 proof.
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

	// Make sure a fresh native dump of v3 keys is on disk.
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
		t.Fatal("subprocess didn't reach the OK line — fix likely regressed")
	}
}

// runLoadKeysOnlyProve runs inside the inner subprocess. It is the
// fresh-process body that exercises the bug.
func runLoadKeysOnlyProve(t *testing.T) {
	loadedAndProveOK(t)
	t.Log("subprocess prove + verify OK")
}
