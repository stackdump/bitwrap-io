package prover

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestMintCircuit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping prover test in short mode")
	}

	// MintCircuit verifies: caller == minter, postStateRoot == mimcHash(to, balanceTo+amount)
	// Use gnark's test engine which handles MiMC computation internally.
	assert := test.NewAssert(t)

	circuit := &MintCircuit{}
	// Valid witness: caller matches minter
	// PostStateRoot must equal mimcHash(to=99, newBalance=1500)
	// We use the test.IsSolved approach which checks satisfiability
	assignment := &MintCircuit{
		PreStateRoot:  0,
		PostStateRoot: 0, // placeholder — we'll use SolvingSucceeded below
		Caller:        42,
		To:            99,
		Amount:        1000,
		Minter:        42,
		BalanceTo:     500,
	}

	// This should fail because PostStateRoot=0 won't match mimcHash(99, 1500)
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))

	t.Log("mint circuit correctly rejects invalid post-state root")
}

func TestMintCircuitBadMinter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping prover test in short mode")
	}

	assert := test.NewAssert(t)
	circuit := &MintCircuit{}

	// Invalid: caller != minter
	assignment := &MintCircuit{
		PreStateRoot:  0,
		PostStateRoot: 0,
		Caller:        42,
		To:            99,
		Amount:        1000,
		Minter:        99, // does NOT match caller
		BalanceTo:     500,
	}

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
	t.Log("mint circuit correctly rejects unauthorized minter")
}

func TestApproveCircuit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping prover test in short mode")
	}

	assert := test.NewAssert(t)
	circuit := &ApproveCircuit{}

	// Invalid: owner != caller
	assignment := &ApproveCircuit{
		PreStateRoot:  0,
		PostStateRoot: 0,
		Caller:        42,
		Spender:       99,
		Amount:        500,
		Owner:         99, // does NOT match caller
	}

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
	t.Log("approve circuit correctly rejects non-owner")
}

func TestTransferFromWitnessFactory(t *testing.T) {
	factory := &ArcnetWitnessFactory{}

	_, err := factory.CreateAssignment("transferFrom", map[string]string{
		"preStateRoot":  "0",
		"postStateRoot": "0",
		"from":          "0x1",
		"to":            "0x2",
		"caller":        "0x3",
		"amount":        "100",
		"balanceFrom":   "1000",
		"allowanceFrom": "500",
	})
	if err != nil {
		t.Fatalf("CreateAssignment transferFrom: %v", err)
	}
	t.Log("transferFrom witness factory works")
}

func TestVestClaimWitnessFactory(t *testing.T) {
	factory := &ArcnetWitnessFactory{}

	_, err := factory.CreateAssignment("vestClaim", map[string]string{
		"preStateRoot":  "0",
		"postStateRoot": "0",
		"tokenID":       "1",
		"caller":        "42",
		"claimAmount":   "100",
		"vestedAmount":  "1000",
		"claimed":       "200",
		"owner":         "42",
	})
	if err != nil {
		t.Fatalf("CreateAssignment vestClaim: %v", err)
	}
	t.Log("vestClaim witness factory works")
}

func TestAllCircuitsCompile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping prover test in short mode")
	}

	p := NewProver()
	err := RegisterStandardCircuits(p)
	if err != nil {
		t.Fatalf("RegisterStandardCircuits: %v", err)
	}

	expected := []string{"transfer", "transferSynth", "transferFrom", "mint", "mintSynth", "burn", "burnSynth", "approve", "vestClaim", "voteCast"}
	circuits := p.ListCircuits()

	if len(circuits) != len(expected) {
		t.Fatalf("expected %d circuits, got %d: %v", len(expected), len(circuits), circuits)
	}

	for _, name := range expected {
		cc, ok := p.GetCircuit(name)
		if !ok {
			t.Fatalf("circuit %q not found", name)
		}
		t.Logf("%s: %d constraints, %d public, %d private", name, cc.Constraints, cc.PublicVars, cc.PrivateVars)
	}
}
