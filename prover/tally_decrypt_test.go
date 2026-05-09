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

// buildTallyDecryptWitness simulates a small poll: encrypt each ballot
// under pkCreator, aggregate per bin, and compute the per-bin tally.
// Returns a satisfying assignment for TallyDecryptCircuit_8.
func buildTallyDecryptWitness(
	t *testing.T,
	skCreator *big.Int,
	ballots [][]int64, // ballots[i][j] ∈ {0,1}, exactly one 1 per row
) *TallyDecryptCircuit_8 {
	t.Helper()
	if len(ballots) == 0 {
		t.Fatalf("need at least one ballot")
	}
	for i, b := range ballots {
		if len(b) != TallyDecryptChoices {
			t.Fatalf("ballot %d wrong width: got %d, want %d", i, len(b), TallyDecryptChoices)
		}
	}

	c := &TallyDecryptCircuit_8{}
	c.SkCreator = skCreator

	g := PedersenG()
	var pk tedwards.PointAffine
	pk.ScalarMultiplication(&g, skCreator)
	c.PkCreator = gtw.Point{X: pointXBig(&pk), Y: pointYBig(&pk)}

	// Per-bin aggregation in the curve.
	tallies := make([]int64, TallyDecryptChoices)
	bins := make([][]Ciphertext, TallyDecryptChoices)
	for i, ballot := range ballots {
		for j := 0; j < TallyDecryptChoices; j++ {
			r := big.NewInt(int64(2_000_000 + i*TallyDecryptChoices + j))
			ct := Encrypt(big.NewInt(ballot[j]), r, &pk)
			bins[j] = append(bins[j], ct)
			tallies[j] += ballot[j]
		}
	}

	for j := 0; j < TallyDecryptChoices; j++ {
		agg := Aggregate(bins[j])
		c.A[j] = gtw.Point{X: pointXBig(&agg.A), Y: pointYBig(&agg.A)}
		c.B[j] = gtw.Point{X: pointXBig(&agg.B), Y: pointYBig(&agg.B)}
		c.Tallies[j] = tallies[j]
	}

	return c
}

// TestTallyDecryptAccepts — happy path: 5 voters across bins {0,1,0,2,1},
// expected tallies = [2,2,1,0,0,0,0,0].
func TestTallyDecryptAccepts(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	assert := test.NewAssert(t)

	ballots := [][]int64{
		{1, 0, 0, 0, 0, 0, 0, 0},
		{0, 1, 0, 0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 1, 0, 0, 0, 0, 0},
		{0, 1, 0, 0, 0, 0, 0, 0},
	}
	w := buildTallyDecryptWitness(t, big.NewInt(0xc0ffee), ballots)
	assert.SolvingSucceeded(&TallyDecryptCircuit_8{}, w, test.WithCurves(ecc.BN254))
}

// TestTallyDecryptRejectsWrongTally — claim 3 votes in bin 0 when only
// 2 were cast. Algebraic identity B = G·T + sk·A breaks.
func TestTallyDecryptRejectsWrongTally(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	assert := test.NewAssert(t)

	ballots := [][]int64{
		{1, 0, 0, 0, 0, 0, 0, 0},
		{0, 1, 0, 0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0, 0, 0, 0},
	}
	w := buildTallyDecryptWitness(t, big.NewInt(0xc0ffee), ballots)
	w.Tallies[0] = 3 // actual is 2
	assert.SolvingFailed(&TallyDecryptCircuit_8{}, w, test.WithCurves(ecc.BN254))
}

// TestTallyDecryptRejectsWrongSk — sk doesn't match published pk.
func TestTallyDecryptRejectsWrongSk(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	assert := test.NewAssert(t)

	ballots := [][]int64{
		{1, 0, 0, 0, 0, 0, 0, 0},
		{0, 1, 0, 0, 0, 0, 0, 0},
	}
	// PkCreator computed from real sk; circuit witness lies about sk.
	w := buildTallyDecryptWitness(t, big.NewInt(0xc0ffee), ballots)
	w.SkCreator = big.NewInt(0xdeadbeef)
	assert.SolvingFailed(&TallyDecryptCircuit_8{}, w, test.WithCurves(ecc.BN254))
}

// TestTallyDecryptRejectsOversizedTally — claim a 17-bit tally; the
// 16-bit range check rejects it.
func TestTallyDecryptRejectsOversizedTally(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	assert := test.NewAssert(t)

	ballots := [][]int64{
		{1, 0, 0, 0, 0, 0, 0, 0},
	}
	w := buildTallyDecryptWitness(t, big.NewInt(0xc0ffee), ballots)
	// Replace bin 0 with an aggregate that decrypts to a 17-bit value.
	g := PedersenG()
	var pk tedwards.PointAffine
	pk.ScalarMultiplication(&g, big.NewInt(0xc0ffee))
	bigTally := int64(1 << 17)
	r := big.NewInt(7777)
	ct := Encrypt(big.NewInt(bigTally), r, &pk)
	w.A[0] = gtw.Point{X: pointXBig(&ct.A), Y: pointYBig(&ct.A)}
	w.B[0] = gtw.Point{X: pointXBig(&ct.B), Y: pointYBig(&ct.B)}
	w.Tallies[0] = bigTally // honest tally — fails range check, not algebraic identity
	assert.SolvingFailed(&TallyDecryptCircuit_8{}, w, test.WithCurves(ecc.BN254))
}

// TestTallyDecryptConstraints — reporting test, like its B3 cousin.
func TestTallyDecryptConstraints(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		&TallyDecryptCircuit_8{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("TallyDecryptCircuit_8: %d constraints, %d secrets, %d public",
		cs.GetNbConstraints(), cs.GetNbSecretVariables(), cs.GetNbPublicVariables())
}
