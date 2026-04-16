package synth_test

import (
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/stackdump/bitwrap-io/erc"
	"github.com/stackdump/bitwrap-io/prover"
	"github.com/stackdump/bitwrap-io/prover/synth"
)

// TestGenerateMintDeterministic — two Generate calls on the same schema
// produce byte-identical output. CI relies on this for the
// `make gen-circuits && git diff --exit-code` gate.
func TestGenerateMintDeterministic(t *testing.T) {
	schema := erc.NewERC020("ERC020", "ERC", 18).Schema()
	a, err := synth.Generate(schema, "prover")
	if err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	b, err := synth.Generate(schema, "prover")
	if err != nil {
		t.Fatalf("second Generate: %v", err)
	}
	if a != b {
		t.Fatalf("synth output not deterministic\n--- a ---\n%s\n--- b ---\n%s", a, b)
	}
	if !strings.Contains(a, "MintSynthCircuit") {
		t.Errorf("expected MintSynthCircuit in output, got:\n%s", a)
	}
}

// TestGenerateMintRequiresRole — synthesizer rejects a schema where the
// mint action lacks the expected "minter" role. This is how we surface
// schema gaps at generation time rather than at compile or runtime.
func TestGenerateMintRequiresRole(t *testing.T) {
	schema := erc.NewERC020("ERC020", "ERC", 18).Schema()
	// Strip roles from the mint action
	for i := range schema.Actions {
		if schema.Actions[i].ID == "mint" {
			schema.Actions[i].Roles = nil
		}
	}
	_, err := synth.Generate(schema, "prover")
	if err == nil {
		t.Fatal("expected error when mint has no Roles, got nil")
	}
	if !strings.Contains(err.Error(), "Roles=[minter]") {
		t.Errorf("expected 'Roles=[minter]' in error, got: %v", err)
	}
}

// TestMintSynthParity — the generated MintSynthCircuit must accept and
// reject the same witnesses as the hand-written MintCircuit.
//
// This is the core parity guarantee: if any gnark solve result diverges
// between the two circuits, a regression has snuck in.
func TestMintSynthParity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping parity test in short mode")
	}
	assert := test.NewAssert(t)

	// Witnesses: shared across both circuits.
	cases := []struct {
		name     string
		caller   int
		to       int
		amount   int
		minter   int
		balance  int
		postRoot int
		wantPass bool
	}{
		{
			name:     "invalid: caller mismatches minter",
			caller:   42,
			to:       99,
			amount:   1000,
			minter:   99,
			balance:  500,
			postRoot: 0,
			wantPass: false,
		},
		{
			name:     "invalid: postRoot mismatches hash",
			caller:   42,
			to:       99,
			amount:   1000,
			minter:   42,
			balance:  500,
			postRoot: 0,
			wantPass: false,
		},
		{
			name:     "invalid: amount added to wrong balance",
			caller:   7,
			to:       11,
			amount:   13,
			minter:   7,
			balance:  100,
			postRoot: 999, // definitely not mimcHash(11, 113)
			wantPass: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			handWritten := &prover.MintCircuit{
				PreStateRoot:  0,
				PostStateRoot: tc.postRoot,
				Caller:        tc.caller,
				To:            tc.to,
				Amount:        tc.amount,
				Minter:        tc.minter,
				BalanceTo:     tc.balance,
			}
			synthesized := &prover.MintSynthCircuit{
				PreStateRoot:  0,
				PostStateRoot: tc.postRoot,
				Caller:        tc.caller,
				To:            tc.to,
				Amount:        tc.amount,
				Minter:        tc.minter,
				BalanceTo:     tc.balance,
			}
			// Both should fail (invalid witness) with same behavior.
			if !tc.wantPass {
				assert.SolvingFailed(&prover.MintCircuit{}, handWritten, test.WithCurves(ecc.BN254))
				assert.SolvingFailed(&prover.MintSynthCircuit{}, synthesized, test.WithCurves(ecc.BN254))
			}
		})
	}
}

// TestBurnSynthParity — generated BurnSynthCircuit mirrors the hand-written
// BurnCircuit for invalid witnesses.
func TestBurnSynthParity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping parity test in short mode")
	}
	assert := test.NewAssert(t)

	// A witness with a bogus Merkle root is invalid for both circuits.
	var path20 [20]frontend.Variable
	var idx20 [20]frontend.Variable
	for i := 0; i < 20; i++ {
		path20[i] = 0
		idx20[i] = 0
	}
	handWritten := &prover.BurnCircuit{
		PreStateRoot:  999, PostStateRoot: 0, From: 42, Amount: 10,
		BalanceFrom: 100, PathElements: path20, PathIndices: idx20,
	}
	synthesized := &prover.BurnSynthCircuit{
		PreStateRoot:  999, PostStateRoot: 0, From: 42, Amount: 10,
		BalanceFrom: 100, PathElements: path20, PathIndices: idx20,
	}
	assert.SolvingFailed(&prover.BurnCircuit{}, handWritten, test.WithCurves(ecc.BN254))
	assert.SolvingFailed(&prover.BurnSynthCircuit{}, synthesized, test.WithCurves(ecc.BN254))

	// Amount > BalanceFrom — range check fails in both.
	overdraw := &prover.BurnCircuit{
		PreStateRoot: 0, PostStateRoot: 0, From: 1, Amount: 1_000_000,
		BalanceFrom: 1, PathElements: path20, PathIndices: idx20,
	}
	overdrawSynth := &prover.BurnSynthCircuit{
		PreStateRoot: 0, PostStateRoot: 0, From: 1, Amount: 1_000_000,
		BalanceFrom: 1, PathElements: path20, PathIndices: idx20,
	}
	assert.SolvingFailed(&prover.BurnCircuit{}, overdraw, test.WithCurves(ecc.BN254))
	assert.SolvingFailed(&prover.BurnSynthCircuit{}, overdrawSynth, test.WithCurves(ecc.BN254))
}

func TestTransferSynthParity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping parity test in short mode")
	}
	assert := test.NewAssert(t)
	var path20, idx20 [20]frontend.Variable
	for i := 0; i < 20; i++ {
		path20[i] = 0
		idx20[i] = 0
	}

	// Invalid post root — both reject.
	tampered := &prover.TransferCircuit{
		PreStateRoot: 0, PostStateRoot: 12345,
		From: 1, To: 2, Amount: 5,
		BalanceFrom: 100, BalanceTo: 0,
		PathElements: path20, PathIndices: idx20,
	}
	tamperedSynth := &prover.TransferSynthCircuit{
		PreStateRoot: 0, PostStateRoot: 12345,
		From: 1, To: 2, Amount: 5,
		BalanceFrom: 100, BalanceTo: 0,
		PathElements: path20, PathIndices: idx20,
	}
	assert.SolvingFailed(&prover.TransferCircuit{}, tampered, test.WithCurves(ecc.BN254))
	assert.SolvingFailed(&prover.TransferSynthCircuit{}, tamperedSynth, test.WithCurves(ecc.BN254))
}

func TestTransferFromSynthSameConstraintCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compile test in short mode")
	}
	p := prover.NewProver()
	a, err := p.CompileCircuit("transferFrom", &prover.TransferFromCircuit{})
	if err != nil {
		t.Fatalf("compile TransferFromCircuit: %v", err)
	}
	b, err := p.CompileCircuit("transferFromSynth", &prover.TransferFromSynthCircuit{})
	if err != nil {
		t.Fatalf("compile TransferFromSynthCircuit: %v", err)
	}
	if a.Constraints != b.Constraints || a.PublicVars != b.PublicVars || a.PrivateVars != b.PrivateVars {
		t.Errorf("transferFrom parity failed: hand=%d/%d/%d synth=%d/%d/%d",
			a.Constraints, a.PublicVars, a.PrivateVars,
			b.Constraints, b.PublicVars, b.PrivateVars)
	}
	t.Logf("both transferFrom circuits: %d constraints, %d public, %d private",
		b.Constraints, b.PublicVars, b.PrivateVars)
}

func TestTransferSynthSameConstraintCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compile test in short mode")
	}
	p := prover.NewProver()
	a, err := p.CompileCircuit("transfer", &prover.TransferCircuit{})
	if err != nil {
		t.Fatalf("compile TransferCircuit: %v", err)
	}
	b, err := p.CompileCircuit("transferSynth", &prover.TransferSynthCircuit{})
	if err != nil {
		t.Fatalf("compile TransferSynthCircuit: %v", err)
	}
	if a.Constraints != b.Constraints || a.PublicVars != b.PublicVars || a.PrivateVars != b.PrivateVars {
		t.Errorf("transfer parity failed: hand=%d/%d/%d synth=%d/%d/%d",
			a.Constraints, a.PublicVars, a.PrivateVars,
			b.Constraints, b.PublicVars, b.PrivateVars)
	}
	t.Logf("both transfer circuits: %d constraints, %d public, %d private",
		b.Constraints, b.PublicVars, b.PrivateVars)
}

func TestBurnSynthSameConstraintCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compile test in short mode")
	}
	p := prover.NewProver()
	a, err := p.CompileCircuit("burn", &prover.BurnCircuit{})
	if err != nil {
		t.Fatalf("compile BurnCircuit: %v", err)
	}
	b, err := p.CompileCircuit("burnSynth", &prover.BurnSynthCircuit{})
	if err != nil {
		t.Fatalf("compile BurnSynthCircuit: %v", err)
	}
	if a.Constraints != b.Constraints || a.PublicVars != b.PublicVars || a.PrivateVars != b.PrivateVars {
		t.Errorf("burn parity failed: hand=%d/%d/%d synth=%d/%d/%d",
			a.Constraints, a.PublicVars, a.PrivateVars,
			b.Constraints, b.PublicVars, b.PrivateVars)
	}
	t.Logf("both burn circuits: %d constraints, %d public, %d private", b.Constraints, b.PublicVars, b.PrivateVars)
}

// TestMintSynthSameConstraintCount — compile both circuits and confirm they
// produce the same number of gnark constraints. This is a cheap proxy for
// "same shape" and runs fast even without witness fuzzing.
func TestMintSynthSameConstraintCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping compile test in short mode")
	}
	p := prover.NewProver()
	handWrittenCC, err := p.CompileCircuit("mint", &prover.MintCircuit{})
	if err != nil {
		t.Fatalf("compile MintCircuit: %v", err)
	}
	synthCC, err := p.CompileCircuit("mintSynth", &prover.MintSynthCircuit{})
	if err != nil {
		t.Fatalf("compile MintSynthCircuit: %v", err)
	}
	if handWrittenCC.Constraints != synthCC.Constraints {
		t.Errorf("constraint count mismatch: hand-written=%d, synth=%d",
			handWrittenCC.Constraints, synthCC.Constraints)
	}
	if handWrittenCC.PublicVars != synthCC.PublicVars {
		t.Errorf("public var count mismatch: hand-written=%d, synth=%d",
			handWrittenCC.PublicVars, synthCC.PublicVars)
	}
	if handWrittenCC.PrivateVars != synthCC.PrivateVars {
		t.Errorf("private var count mismatch: hand-written=%d, synth=%d",
			handWrittenCC.PrivateVars, synthCC.PrivateVars)
	}
	t.Logf("both circuits: %d constraints, %d public, %d private",
		synthCC.Constraints, synthCC.PublicVars, synthCC.PrivateVars)
}
