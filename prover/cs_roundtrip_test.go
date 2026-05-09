package prover

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// TestCSRoundTripNativeProve — compile, write cs+pk+vk to bytes, then
// read them back and Prove. This is the same byte path the WASM
// worker uses via /api/keys, but executed entirely on native Go.
// If this passes, the round-trip works in native; if WASM still
// fails after this, the bug is in WASM-side gnark deserialization.
func TestCSRoundTripNativeProve(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles voteCastHomomorphic_8")
	}
	dump, err := os.ReadFile("/tmp/v3-witness-dump.json")
	if err != nil {
		t.Skipf("no dump at /tmp/v3-witness-dump.json")
	}
	var d struct {
		PollID  string            `json:"pollId"`
		Witness map[string]string `json:"witness"`
	}
	if err := json.Unmarshal(dump, &d); err != nil {
		t.Fatal(err)
	}

	// Fresh compile.
	p := NewProver()
	cc, err := p.CompileCircuit("voteCastHomomorphic_8", &VoteCastHomomorphicCircuit_8{})
	if err != nil {
		t.Fatal(err)
	}

	// Round-trip cs.
	var csBuf bytes.Buffer
	if _, err := cc.CS.WriteTo(&csBuf); err != nil {
		t.Fatal(err)
	}
	cs2 := groth16.NewCS(ecc.BN254)
	if _, err := cs2.ReadFrom(&csBuf); err != nil {
		t.Fatal(err)
	}

	// Round-trip pk.
	var pkBuf bytes.Buffer
	if _, err := cc.ProvingKey.WriteTo(&pkBuf); err != nil {
		t.Fatal(err)
	}
	pk2 := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk2.ReadFrom(&pkBuf); err != nil {
		t.Fatal(err)
	}

	// Round-trip vk.
	var vkBuf bytes.Buffer
	if _, err := cc.VerifyingKey.WriteTo(&vkBuf); err != nil {
		t.Fatal(err)
	}
	vk2 := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk2.ReadFrom(&vkBuf); err != nil {
		t.Fatal(err)
	}

	t.Logf("round-trip sizes: cs=%dB pk=%dB vk=%dB",
		csBuf.Len()+func() int { return 0 }(), pkBuf.Len()+0, vkBuf.Len()+0)
	t.Logf("cs2 constraints=%d", cs2.GetNbConstraints())

	assignment, err := buildVoteCastHomomorphic8Assignment(d.Witness)
	if err != nil {
		t.Fatal(err)
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	// Cast cs2 to constraint.ConstraintSystem (groth16.NewCS returns interface).
	csIface, ok := cs2.(constraint.ConstraintSystem)
	if !ok {
		t.Fatalf("cs2 is not a ConstraintSystem: %T", cs2)
	}
	proof, err := groth16.Prove(csIface, pk2, full)
	if err != nil {
		t.Fatalf("prove from round-tripped cs+pk: %v", err)
	}
	pubW, _ := full.Public()
	if err := groth16.Verify(proof, vk2, pubW); err != nil {
		t.Fatalf("verify with round-tripped vk: %v", err)
	}
	t.Log("native round-trip prove + verify OK")
}
