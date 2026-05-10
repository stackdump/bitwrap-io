package prover

import (
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	babyjubjub "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// runLoadKeysOnlyProve is the inner subprocess body for
// TestLoadKeysOnlyProveSubprocess. It loads the v3 vote circuit's
// keys + a dumped witness from disk and proves — but only after
// nudging gnark-crypto's twisted-Edwards lazy init via
// `babyjubjub.GetEdwardsCurve()`. Without that nudge the prove fails
// at "constraint #N is not satisfied" mid-scalarMulFakeGLV because
// `PointExtended.Add` reads `curveParams.D == 0`. This test is
// effectively the regression check for the workaround that
// `cmd/prover-wasm/main.go::main` does at start-up.
//
// Lives in its own file so it doesn't share imports with sibling
// tests that would otherwise pre-warm the lazy init out of band.
func runLoadKeysOnlyProve(t *testing.T) {
	const name = "voteCastHomomorphic_8"

	// THIS LINE IS THE WORKAROUND. Removing it makes the prove below
	// fail with the issue #3 symptom. Keep this comment honest if
	// gnark-crypto upstream ever lands the missing initOnce.Do call.
	_ = babyjubjub.GetEdwardsCurve()

	csPath := "/tmp/native-keys-" + name + ".cs"
	pkPath := "/tmp/native-keys-" + name + ".pk"
	vkPath := "/tmp/native-keys-" + name + ".vk"

	cs := groth16.NewCS(ecc.BN254)
	openInto(t, csPath, cs.ReadFrom)
	pk := groth16.NewProvingKey(ecc.BN254)
	openInto(t, pkPath, pk.ReadFrom)
	vk := groth16.NewVerifyingKey(ecc.BN254)
	openInto(t, vkPath, vk.ReadFrom)

	dump, err := os.ReadFile("/tmp/v3-witness-dump.json")
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Witness map[string]string `json:"witness"`
	}
	if err := json.Unmarshal(dump, &d); err != nil {
		t.Fatal(err)
	}
	assignment, err := buildVoteCastHomomorphic8Assignment(d.Witness)
	if err != nil {
		t.Fatal(err)
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	csIface := cs.(constraint.ConstraintSystem)
	proof, err := groth16.Prove(csIface, pk, full)
	if err != nil {
		t.Fatalf("prove (subprocess, no prior compile): %v", err)
	}
	pubW, _ := full.Public()
	if err := groth16.Verify(proof, vk, pubW); err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Log("subprocess prove + verify OK")
}

// openInto opens path and pipes its content into the given ReadFrom.
func openInto(t *testing.T, path string, read func(r io.Reader) (int64, error)) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := read(f); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
}
