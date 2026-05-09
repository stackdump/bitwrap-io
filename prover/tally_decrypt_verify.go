package prover

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// TallyDecryptProofInputs is the authoritative set of public inputs
// the server (not the client) supplies to verify the creator's
// decrypt proof. The aggregate ciphertexts are recomputed by the
// server itself from the persisted votes — a malicious creator
// can't bind the proof to an aggregate that doesn't match the votes
// on disk.
type TallyDecryptProofInputs struct {
	PkCreator tedwards.PointAffine
	A         []tedwards.PointAffine // K entries, server-recomputed aggregate
	B         []tedwards.PointAffine // K entries, server-recomputed aggregate
	Tallies   []int64                // K entries, claimed plaintext
}

// VerifyTallyDecryptProofBytes verifies a v3 close proof. Caller is
// responsible for prior validation of PkCreator (subgroup check) and
// for having recomputed the aggregate from the server's view of the
// votes.
func VerifyTallyDecryptProofBytes(p *Prover, proofBytes []byte, in TallyDecryptProofInputs) error {
	if len(in.A) != TallyDecryptChoices || len(in.B) != TallyDecryptChoices || len(in.Tallies) != TallyDecryptChoices {
		return fmt.Errorf("expected %d aggregates and tallies, got A=%d B=%d T=%d",
			TallyDecryptChoices, len(in.A), len(in.B), len(in.Tallies))
	}
	cc, ok := p.GetCircuit("tallyDecrypt_8")
	if !ok {
		return fmt.Errorf("tallyDecrypt_8 circuit not registered")
	}

	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("invalid proof bytes: %w", err)
	}

	var assignment TallyDecryptCircuit_8
	assignment.PkCreator = pointToVar(&in.PkCreator)
	for j := 0; j < TallyDecryptChoices; j++ {
		assignment.A[j] = pointToVar(&in.A[j])
		assignment.B[j] = pointToVar(&in.B[j])
		assignment.Tallies[j] = big.NewInt(in.Tallies[j])
	}

	pubWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("public witness build: %w", err)
	}
	if err := groth16.Verify(proof, cc.VerifyingKey, pubWitness); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}
	return nil
}
