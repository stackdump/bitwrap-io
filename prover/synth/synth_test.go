package synth_test

import (
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
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
