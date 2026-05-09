package prover

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gtw "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/test"
)

// buildHomomorphicWitness constructs a satisfying assignment for the
// VoteCastHomomorphicCircuit_8.
//
// Voter is placed at Merkle index 0 with all sibling hashes = 0 — a
// minimal but real registry of depth homomorphicMerkleDepth.
func buildHomomorphicWitness(
	t *testing.T,
	pollID, secret, weight int64,
	choice int,
	maxChoices int,
	skCreator *big.Int,
) *VoteCastHomomorphicCircuit_8 {
	t.Helper()
	if choice < 0 || choice >= maxChoices {
		t.Fatalf("test bug: choice %d outside [0, %d)", choice, maxChoices)
	}
	if maxChoices > VoteCastHomomorphicChoices {
		t.Fatalf("test bug: maxChoices %d > K %d", maxChoices, VoteCastHomomorphicChoices)
	}

	c := &VoteCastHomomorphicCircuit_8{}
	c.PollID = pollID
	c.MaxChoices = maxChoices
	c.VoterSecret = secret
	c.VoterWeight = weight

	// Merkle: leaf = mimc(secret, weight), zero siblings, indices = 0.
	leaf := MiMCHashBigInt(big.NewInt(secret), big.NewInt(weight))
	current := leaf
	zero := big.NewInt(0)
	for i := 0; i < homomorphicMerkleDepth; i++ {
		c.PathElements[i] = zero
		c.PathIndices[i] = 0
		current = MiMCHashBigInt(current, zero)
	}
	c.VoterRegistryRoot = current
	c.Nullifier = MiMCHashBigInt(big.NewInt(secret), big.NewInt(pollID))

	// pk = G · sk
	g := PedersenG()
	var pk tedwards.PointAffine
	pk.ScalarMultiplication(&g, skCreator)
	c.PkCreator = gtw.Point{X: pointXBig(&pk), Y: pointYBig(&pk)}

	// Per-bin one-hot vector and randomness.
	for j := 0; j < VoteCastHomomorphicChoices; j++ {
		var vj int64
		if j == choice {
			vj = 1
		}
		// Distinct deterministic randomness per bin so each ciphertext
		// is unique even when v=0.
		r := big.NewInt(int64(1_000_000 + j*37 + 1))
		ct := Encrypt(big.NewInt(vj), r, &pk)

		c.V[j] = vj
		c.R[j] = r
		c.CtA[j] = gtw.Point{X: pointXBig(&ct.A), Y: pointYBig(&ct.A)}
		c.CtB[j] = gtw.Point{X: pointXBig(&ct.B), Y: pointYBig(&ct.B)}
	}

	return c
}

// pointXBig / pointYBig — convert fr.Element coordinates to *big.Int
// suitable for gnark frontend.Variable assignment.
func pointXBig(p *tedwards.PointAffine) *big.Int {
	var b big.Int
	p.X.BigInt(&b)
	return &b
}
func pointYBig(p *tedwards.PointAffine) *big.Int {
	var b big.Int
	p.Y.BigInt(&b)
	return &b
}

// TestVoteCastHomomorphicAccepts — happy path: K=8, MaxChoices=3,
// voter selects bin 1.
func TestVoteCastHomomorphicAccepts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping prover test in short mode")
	}
	assert := test.NewAssert(t)

	w := buildHomomorphicWitness(t,
		/*pollID*/ 42, /*secret*/ 100, /*weight*/ 1,
		/*choice*/ 1, /*maxChoices*/ 3,
		big.NewInt(0xc0ffee))

	assert.SolvingSucceeded(&VoteCastHomomorphicCircuit_8{}, w, test.WithCurves(ecc.BN254))
}

// Refusal cases — each tweaks one constraint and asserts the solver fails.

// Two bins set: violates Σ V = 1.
func TestVoteCastHomomorphicRejectsTwoHot(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	assert := test.NewAssert(t)

	w := buildHomomorphicWitness(t, 42, 100, 1, 1, 3, big.NewInt(0xc0ffee))
	w.V[2] = 1 // now V = [0,1,1,0,...]
	// CtA/CtB still bind to old V; ElGamal binding will also fail, but
	// the one-hot violation is sufficient.

	assert.SolvingFailed(&VoteCastHomomorphicCircuit_8{}, w, test.WithCurves(ecc.BN254))
}

// V[j] non-binary: violates AssertIsBoolean.
func TestVoteCastHomomorphicRejectsNonBoolean(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	assert := test.NewAssert(t)

	w := buildHomomorphicWitness(t, 42, 100, 1, 1, 3, big.NewInt(0xc0ffee))
	w.V[1] = 2 // not boolean, also breaks Σ = 1
	assert.SolvingFailed(&VoteCastHomomorphicCircuit_8{}, w, test.WithCurves(ecc.BN254))
}

// Voter selects bin 5 with MaxChoices=3 — violates the range bound.
func TestVoteCastHomomorphicRejectsOutOfRangeBin(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	assert := test.NewAssert(t)

	w := buildHomomorphicWitness(t, 42, 100, 1, 0, 3, big.NewInt(0xc0ffee))
	// rebuild ballot at bin 5 with MaxChoices still 3
	w.V[0] = 0
	w.V[5] = 1
	g := PedersenG()
	var pk tedwards.PointAffine
	pk.ScalarMultiplication(&g, big.NewInt(0xc0ffee))
	for j := 0; j < VoteCastHomomorphicChoices; j++ {
		var vj int64
		if j == 5 {
			vj = 1
		}
		r := big.NewInt(int64(1_000_000 + j*37 + 1))
		ct := Encrypt(big.NewInt(vj), r, &pk)
		w.CtA[j] = gtw.Point{X: pointXBig(&ct.A), Y: pointYBig(&ct.A)}
		w.CtB[j] = gtw.Point{X: pointXBig(&ct.B), Y: pointYBig(&ct.B)}
	}
	assert.SolvingFailed(&VoteCastHomomorphicCircuit_8{}, w, test.WithCurves(ecc.BN254))
}

// Forged ElGamal: voter claims v=1 in bin 0 but ciphertext encrypts v=0.
func TestVoteCastHomomorphicRejectsBadElGamal(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	assert := test.NewAssert(t)

	w := buildHomomorphicWitness(t, 42, 100, 1, 0, 3, big.NewInt(0xc0ffee))
	// Replace CtB[0] with an encryption of 0 (instead of 1).
	g := PedersenG()
	var pk tedwards.PointAffine
	pk.ScalarMultiplication(&g, big.NewInt(0xc0ffee))
	r := big.NewInt(99)
	ct := Encrypt(big.NewInt(0), r, &pk)
	w.CtA[0] = gtw.Point{X: pointXBig(&ct.A), Y: pointYBig(&ct.A)}
	w.CtB[0] = gtw.Point{X: pointXBig(&ct.B), Y: pointYBig(&ct.B)}
	w.R[0] = r
	// V[0] still 1, so claimed plaintext doesn't match ciphertext.

	assert.SolvingFailed(&VoteCastHomomorphicCircuit_8{}, w, test.WithCurves(ecc.BN254))
}

// Wrong nullifier: violates mimc binding.
func TestVoteCastHomomorphicRejectsBadNullifier(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	assert := test.NewAssert(t)

	w := buildHomomorphicWitness(t, 42, 100, 1, 1, 3, big.NewInt(0xc0ffee))
	w.Nullifier = big.NewInt(0xdeadbeef)

	assert.SolvingFailed(&VoteCastHomomorphicCircuit_8{}, w, test.WithCurves(ecc.BN254))
}

// TestVoteCastHomomorphicConstraints prints constraint count for
// proving-cost regression tracking. Doesn't fail on numbers — it's a
// reporting test.
func TestVoteCastHomomorphicConstraints(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		&VoteCastHomomorphicCircuit_8{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("VoteCastHomomorphicCircuit_8: %d constraints, %d secrets, %d public",
		cs.GetNbConstraints(), cs.GetNbSecretVariables(), cs.GetNbPublicVariables())
}
