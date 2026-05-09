package prover

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	gtw "github.com/consensys/gnark/std/algebra/native/twistededwards"
)

// HomomorphicCiphertextHex is the wire-format ciphertext shape — paired
// 32-byte compressed hex strings. Mirrors store.HomomorphicCiphertext
// without a circular import.
type HomomorphicCiphertextHex struct {
	A string
	B string
}

// VoteCastHomomorphicProofInputs carries the authoritative public-input
// data that the server (not the client) supplies when verifying a v3
// vote proof. Building the witness server-side from authoritative
// fields means a client can't fool the verifier by submitting a proof
// for a different nullifier or ciphertext set than it claims to.
type VoteCastHomomorphicProofInputs struct {
	PollID         *big.Int
	RegistryRoot   *big.Int
	Nullifier      *big.Int
	MaxChoices     int
	PkCreator      tedwards.PointAffine // already validated on-curve / in-subgroup
	Ciphertexts    []Ciphertext         // exactly K
}

// VerifyVoteCastHomomorphicProofBytes verifies a v3 per-voter ZK proof
// against an authoritatively-built public witness. The caller is
// responsible for ensuring PkCreator is in the prime-order subgroup
// and each ciphertext point decodes cleanly; this function does the
// proof check only.
func VerifyVoteCastHomomorphicProofBytes(p *Prover, proofBytes []byte, in VoteCastHomomorphicProofInputs) error {
	if len(in.Ciphertexts) != VoteCastHomomorphicChoices {
		return fmt.Errorf("expected %d ciphertexts, got %d", VoteCastHomomorphicChoices, len(in.Ciphertexts))
	}
	cc, ok := p.GetCircuit("voteCastHomomorphic_8")
	if !ok {
		return fmt.Errorf("voteCastHomomorphic_8 circuit not registered")
	}

	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("invalid proof bytes: %w", err)
	}

	var assignment VoteCastHomomorphicCircuit_8
	assignment.PollID = in.PollID
	assignment.VoterRegistryRoot = in.RegistryRoot
	assignment.Nullifier = in.Nullifier
	assignment.MaxChoices = in.MaxChoices
	assignment.PkCreator = pointToVar(&in.PkCreator)
	for j := 0; j < VoteCastHomomorphicChoices; j++ {
		assignment.CtA[j] = pointToVar(&in.Ciphertexts[j].A)
		assignment.CtB[j] = pointToVar(&in.Ciphertexts[j].B)
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

func pointToVar(p *tedwards.PointAffine) gtw.Point {
	var x, y big.Int
	p.X.BigInt(&x)
	p.Y.BigInt(&y)
	return gtw.Point{X: &x, Y: &y}
}
