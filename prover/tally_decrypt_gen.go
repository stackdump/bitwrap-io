// Hand-written for Phase B / vote schema v3 (B4 deliverable).
// See prover/vote_homomorphic_gen.go for the per-voter circuit; this
// circuit closes the protocol on the creator side: given the bin-wise
// aggregate ciphertexts and a claimed tally per bin, prove the creator
// holds the secret key behind pkCreator and that the tallies are the
// actual decryptions of the aggregate ciphertexts.

package prover

import (
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	tedwards "github.com/consensys/gnark/std/algebra/native/twistededwards"
)

// TallyDecryptChoices is the bin-count K for the K=8 variant.
const TallyDecryptChoices = 8

// TallyDecryptTallyBits caps each per-bin tally at 2^16 - 1, which
// covers any plausible poll size. Without this bound a malicious
// prover could claim an out-of-range tally that still satisfies the
// algebraic identity (the group has order ~2^251); the on-chain
// verifier can rely on tallies fitting in uint16.
const TallyDecryptTallyBits = 16

// TallyDecryptCircuit_8 — creator's proof that the published tallies
// are the actual decryptions of the aggregate ciphertexts (K=8). See
// docs/homomorphic-tally-spec.md § "Tally decryption".
//
// Public:
//
//	PkCreator (X,Y)
//	Aggregates A[K], B[K]   per-bin aggregate ciphertexts
//	Tallies[K]              claimed plaintext tally per bin
//
// Private:
//
//	SkCreator
//
// Constraints:
//
//  1. PkCreator = G · SkCreator
//  2. For each bin j:  B_j = G · Tallies[j] + A_j · SkCreator
//  3. Each Tallies[j] fits in 16 bits.
//
// Constraint count is dominated by K+1 scalar mults of full-width
// scalar against G or A, plus K small-width scalar mults against G.
// Roughly 1/4 the cost of VoteCastHomomorphicCircuit_8.
type TallyDecryptCircuit_8 struct {
	PkCreator tedwards.Point                          `gnark:",public"`
	A         [TallyDecryptChoices]tedwards.Point     `gnark:",public"`
	B         [TallyDecryptChoices]tedwards.Point     `gnark:",public"`
	Tallies   [TallyDecryptChoices]frontend.Variable  `gnark:",public"`

	SkCreator frontend.Variable
}

func (c *TallyDecryptCircuit_8) Define(api frontend.API) error {
	curve, err := tedwards.NewEdCurve(api, twistededwards.BN254)
	if err != nil {
		return err
	}
	params := curve.Params()
	G := tedwards.Point{X: params.Base[0], Y: params.Base[1]}

	// 1. PkCreator = G · SkCreator. Binds the proof to the public key
	//    that voters used when constructing their ciphertexts.
	expectedPk := curve.ScalarMul(G, c.SkCreator)
	api.AssertIsEqual(expectedPk.X, c.PkCreator.X)
	api.AssertIsEqual(expectedPk.Y, c.PkCreator.Y)

	// 2. For each bin: B_j = G · Tallies[j] + A_j · SkCreator.
	//    Separate ScalarMul + Add measures cheaper than gnark's
	//    DoubleBaseScalarMul because the latter assumes both scalars
	//    are full Fr width (~250 bits) and doesn't exploit the
	//    16-bit bound on Tallies. A future optimization is to inline
	//    a 16-bit binary-recomposition mult for G · Tallies[j] —
	//    saves ~2-3k constraints per bin.
	// 3. Tallies[j] fits in 16 bits.
	for j := 0; j < TallyDecryptChoices; j++ {
		api.ToBinary(c.Tallies[j], TallyDecryptTallyBits)

		gTally := curve.ScalarMul(G, c.Tallies[j])
		skA := curve.ScalarMul(c.A[j], c.SkCreator)
		expectedB := curve.Add(gTally, skA)
		api.AssertIsEqual(expectedB.X, c.B[j].X)
		api.AssertIsEqual(expectedB.Y, c.B[j].Y)
	}

	return nil
}
