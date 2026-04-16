package prover

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

// buildTallyWitness constructs a satisfying TallyProofCircuit assignment
// from a set of reveals. Inactive slots are zero-padded. Returns the
// assignment populated with both public and private fields so the solver
// can check the full constraint system.
func buildTallyWitness(t *testing.T, pollID int64, reveals []struct {
	secret int64
	choice int64
}) *TallyProofCircuit {
	t.Helper()

	if len(reveals) > TallyProofMaxReveals {
		t.Fatalf("test bug: %d reveals exceeds circuit capacity %d", len(reveals), TallyProofMaxReveals)
	}

	var c TallyProofCircuit
	c.PollID = pollID
	c.NumReveals = len(reveals)

	pollBig := big.NewInt(pollID)
	tallies := make([]int64, TallyProofMaxChoices)

	for i := 0; i < TallyProofMaxReveals; i++ {
		if i < len(reveals) {
			r := reveals[i]
			secretBig := big.NewInt(r.secret)
			choiceBig := big.NewInt(r.choice)
			commit := MiMCHashBigInt(secretBig, choiceBig)
			nullifier := MiMCHashBigInt(secretBig, pollBig)

			c.Secrets[i] = r.secret
			c.Choices[i] = r.choice
			c.Active[i] = 1
			c.Commitments[i] = commit
			c.Nullifiers[i] = nullifier

			if r.choice < 0 || r.choice >= TallyProofMaxChoices {
				t.Fatalf("test bug: choice %d out of range [0, %d)", r.choice, TallyProofMaxChoices)
			}
			tallies[r.choice]++
		} else {
			c.Secrets[i] = 0
			c.Choices[i] = 0
			c.Active[i] = 0
			c.Commitments[i] = 0
			c.Nullifiers[i] = 0
		}
	}

	for j := 0; j < TallyProofMaxChoices; j++ {
		c.Tallies[j] = tallies[j]
	}

	return &c
}

// TestTallyProofCircuitAccepts — happy path: three reveals, choices
// {0, 1, 0}, maxChoices=3. Expected tally = [2, 1, 0, 0, 0, 0, 0, 0].
// The circuit must solve.
func TestTallyProofCircuitAccepts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping prover test in short mode")
	}
	assert := test.NewAssert(t)

	reveals := []struct{ secret, choice int64 }{
		{secret: 100, choice: 0},
		{secret: 200, choice: 1},
		{secret: 300, choice: 0},
	}
	assignment := buildTallyWitness(t, 42, reveals)

	assert.SolvingSucceeded(&TallyProofCircuit{}, assignment, test.WithCurves(ecc.BN254))
}

// TestTallyProofCircuitRejectsWrongTally — a single off-by-one in the
// claimed tally vector must make the circuit unsatisfiable.
func TestTallyProofCircuitRejectsWrongTally(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping prover test in short mode")
	}
	assert := test.NewAssert(t)

	reveals := []struct{ secret, choice int64 }{
		{secret: 100, choice: 0},
		{secret: 200, choice: 1},
		{secret: 300, choice: 0},
	}
	assignment := buildTallyWitness(t, 42, reveals)
	assignment.Tallies[0] = 3 // lie: claim three votes for choice 0 when only two exist

	assert.SolvingFailed(&TallyProofCircuit{}, assignment, test.WithCurves(ecc.BN254))
}

// TestTallyProofCircuitRejectsForgedCommitment — if a commitment doesn't
// match mimc(secret, choice) for an active slot, the proof must fail.
// This guards against a malicious prover swapping in fake reveals.
func TestTallyProofCircuitRejectsForgedCommitment(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping prover test in short mode")
	}
	assert := test.NewAssert(t)

	reveals := []struct{ secret, choice int64 }{
		{secret: 100, choice: 0},
		{secret: 200, choice: 1},
	}
	assignment := buildTallyWitness(t, 42, reveals)
	assignment.Commitments[0] = big.NewInt(0xdeadbeef) // bogus commitment

	assert.SolvingFailed(&TallyProofCircuit{}, assignment, test.WithCurves(ecc.BN254))
}

// TestTallyProofCircuitRejectsWrongPollID — nullifier is bound to PollID.
// Swapping the pollID must invalidate the nullifier check, catching
// replay attempts across polls.
func TestTallyProofCircuitRejectsWrongPollID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping prover test in short mode")
	}
	assert := test.NewAssert(t)

	reveals := []struct{ secret, choice int64 }{
		{secret: 100, choice: 0},
	}
	assignment := buildTallyWitness(t, 42, reveals)
	assignment.PollID = 99 // different poll — nullifier no longer matches

	assert.SolvingFailed(&TallyProofCircuit{}, assignment, test.WithCurves(ecc.BN254))
}

// TestTallyProofCircuitRejectsActiveMaskMismatch — if Active[i] disagrees
// with NumReveals (e.g., a voter flipped inactive -> active to inflate
// tallies), sum(Active) != NumReveals and the circuit must fail.
func TestTallyProofCircuitRejectsActiveMaskMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping prover test in short mode")
	}
	assert := test.NewAssert(t)

	reveals := []struct{ secret, choice int64 }{
		{secret: 100, choice: 0},
		{secret: 200, choice: 1},
	}
	assignment := buildTallyWitness(t, 42, reveals)
	assignment.Active[5] = 1 // lie: claim an extra active slot without changing NumReveals

	assert.SolvingFailed(&TallyProofCircuit{}, assignment, test.WithCurves(ecc.BN254))
}

// TestTallyProofCircuitRoundTrip runs the full Groth16 setup + prove +
// verify pipeline. Slower than the solver-only tests but guarantees the
// circuit produces real proofs end-to-end.
func TestTallyProofCircuitRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping prover test in short mode")
	}

	p := NewProver()
	cc, err := p.CompileCircuit("tallyProof", &TallyProofCircuit{})
	if err != nil {
		t.Fatalf("compile tallyProof: %v", err)
	}
	p.StoreCircuit("tallyProof", cc)

	reveals := []struct{ secret, choice int64 }{
		{secret: 11, choice: 2},
		{secret: 22, choice: 0},
		{secret: 33, choice: 2},
		{secret: 44, choice: 1},
	}
	assignment := buildTallyWitness(t, 1234, reveals)

	if err := p.Verify("tallyProof", assignment); err != nil {
		t.Fatalf("full prove+verify round trip: %v", err)
	}

	t.Logf("tallyProof: %d constraints, %d public, %d private", cc.Constraints, cc.PublicVars, cc.PrivateVars)
}

// TestTallyProofSerializedVerify covers the path used by the in-browser
// "Verify Proof" button: serialize the proof + public witness to bytes,
// then re-verify solely from those bytes (simulating an external
// verifier that never saw the prover's internal state).
func TestTallyProofSerializedVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping prover serialization test in short mode")
	}

	p := NewProver()
	cc, err := p.CompileCircuit("tallyProof", &TallyProofCircuit{})
	if err != nil {
		t.Fatalf("compile tallyProof: %v", err)
	}
	p.StoreCircuit("tallyProof", cc)

	reveals := []struct{ secret, choice int64 }{
		{secret: 91, choice: 3},
		{secret: 92, choice: 3},
		{secret: 93, choice: 0},
	}
	assignment := buildTallyWitness(t, 5555, reveals)

	artifact, err := ProveTallyProof(p, assignment)
	if err != nil {
		t.Fatalf("ProveTallyProof: %v", err)
	}
	if len(artifact.ProofBytes) == 0 || len(artifact.PublicWitnessBytes) == 0 {
		t.Fatalf("artifact missing bytes: proof=%d pub=%d", len(artifact.ProofBytes), len(artifact.PublicWitnessBytes))
	}

	// Happy path: clean bytes verify.
	if err := VerifyTallyProofBytes(p, artifact.ProofBytes, artifact.PublicWitnessBytes); err != nil {
		t.Fatalf("clean verify: %v", err)
	}

	// Negative: tamper the proof bytes. Flip one byte in the middle of the
	// serialized proof — any bit change should break the pairing check.
	tampered := append([]byte(nil), artifact.ProofBytes...)
	tampered[len(tampered)/2] ^= 0xff
	if err := VerifyTallyProofBytes(p, tampered, artifact.PublicWitnessBytes); err == nil {
		t.Error("verify accepted tampered proof bytes — expected failure")
	}

	// Negative: tamper the public witness body. Mutate a byte past the
	// 12-byte header so the body length stays aligned to the element size.
	tamperedPub := append([]byte(nil), artifact.PublicWitnessBytes...)
	if len(tamperedPub) < 48 {
		t.Fatalf("public witness unexpectedly short: %d", len(tamperedPub))
	}
	tamperedPub[len(tamperedPub)-1] ^= 0x01
	if err := VerifyTallyProofBytes(p, artifact.ProofBytes, tamperedPub); err == nil {
		t.Error("verify accepted tampered public witness — expected failure")
	}
}
