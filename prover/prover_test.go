package prover

import (
	"testing"
)

func TestMintCircuitProve(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping prover test in short mode")
	}

	p := NewProver()

	// Register only mint (simplest circuit, fastest to compile)
	cc, err := p.CompileCircuit("mint", &MintCircuit{})
	if err != nil {
		t.Fatalf("CompileCircuit: %v", err)
	}
	p.StoreCircuit("mint", cc)
	t.Logf("mint circuit: %d constraints, %d public, %d private", cc.Constraints, cc.PublicVars, cc.PrivateVars)

	// Create a valid witness: caller == minter
	factory := &ArcnetWitnessFactory{}
	assignment, err := factory.CreateAssignment("mint", map[string]string{
		"preStateRoot":  "0",
		"postStateRoot": "0",
		"caller":        "42",
		"to":            "99",
		"amount":        "1000",
		"minter":        "42", // matches caller
		"balanceTo":     "500",
	})
	if err != nil {
		t.Fatalf("CreateAssignment: %v", err)
	}

	// Generate proof
	result, err := p.Prove("mint", assignment)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if result.CircuitName != "mint" {
		t.Fatalf("expected circuit_name=mint, got %s", result.CircuitName)
	}
	if len(result.PublicInputs) == 0 {
		t.Fatal("expected public inputs")
	}
	if len(result.RawProof) == 0 {
		t.Fatal("expected raw proof data")
	}
	t.Logf("proof generated: %d public inputs, %d raw proof elements", len(result.PublicInputs), len(result.RawProof))
}

func TestApproveCircuitProve(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping prover test in short mode")
	}

	p := NewProver()
	cc, err := p.CompileCircuit("approve", &ApproveCircuit{})
	if err != nil {
		t.Fatalf("CompileCircuit: %v", err)
	}
	p.StoreCircuit("approve", cc)

	factory := &ArcnetWitnessFactory{}
	assignment, err := factory.CreateAssignment("approve", map[string]string{
		"preStateRoot":  "0",
		"postStateRoot": "0",
		"caller":        "42",
		"spender":       "99",
		"amount":        "500",
		"owner":         "42", // matches caller
	})
	if err != nil {
		t.Fatalf("CreateAssignment: %v", err)
	}

	result, err := p.Prove("approve", assignment)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if result.CircuitName != "approve" {
		t.Fatalf("expected circuit_name=approve, got %s", result.CircuitName)
	}
	t.Logf("approve proof: %d public inputs", len(result.PublicInputs))
}
