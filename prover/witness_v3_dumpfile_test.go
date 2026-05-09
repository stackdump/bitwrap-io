package prover

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// TestProveFromDumpedWitness — load /tmp/v3-witness-dump.json (produced
// by e2e/v3_dump_witness.spec.js) and try to Prove + Verify against
// a freshly-compiled circuit. If this passes, the JS witness shape
// is correct; the WASM-side prove failure must be in the WASM
// constraint-system load or witness-factory path.
func TestProveFromDumpedWitness(t *testing.T) {
	const dumpPath = "/tmp/v3-witness-dump.json"
	data, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Skipf("no dump at %s; run e2e/v3_dump_witness.spec.js first", dumpPath)
	}
	var dump struct {
		PollID  string            `json:"pollId"`
		Witness map[string]string `json:"witness"`
	}
	if err := json.Unmarshal(data, &dump); err != nil {
		t.Fatalf("decode dump: %v", err)
	}

	t.Logf("loaded witness for poll %s with %d fields", dump.PollID, len(dump.Witness))

	assignment, err := buildVoteCastHomomorphic8Assignment(dump.Witness)
	if err != nil {
		t.Fatalf("buildAssignment: %v", err)
	}

	p := NewProver()
	cc, err := p.CompileCircuit("voteCastHomomorphic_8", &VoteCastHomomorphicCircuit_8{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	proof, err := groth16.Prove(cc.CS, cc.ProvingKey, full)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	pubW, _ := full.Public()
	if err := groth16.Verify(proof, cc.VerifyingKey, pubW); err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Log("dump witness prove + verify OK")
}
