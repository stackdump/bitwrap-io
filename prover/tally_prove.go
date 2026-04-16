package prover

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

// TallyProofArtifact is the full output of a tally-proof generation:
// raw gnark proof + public witness bytes (for JS / Go re-verification),
// plus decoded public inputs for human inspection and for binding the
// proof to known poll state (pollId, commitments, nullifiers, tallies).
type TallyProofArtifact struct {
	ProofBytes         []byte
	PublicWitnessBytes []byte
	PublicInputs       []string // hex-encoded, in circuit public-field order
}

// ProveTallyProof runs groth16.Prove against a TallyProofCircuit16
// assignment. Kept as a thin wrapper around ProveTally for call sites
// that pre-date the sized variants. New code should use ProveTally
// directly with a size-specific circuit name.
func ProveTallyProof(p *Prover, assignment *TallyProofCircuit16) (*TallyProofArtifact, error) {
	return ProveTally(p, "tallyProof", assignment)
}

// ProveTally is the size-agnostic prove path used by all TallyProofCircuitN
// variants. Runs groth16.Prove, serializes, self-verifies, and returns
// both wire-format bytes and decoded public inputs.
func ProveTally(p *Prover, circuitName string, assignment frontend.Circuit) (*TallyProofArtifact, error) {
	cc, ok := p.GetCircuit(circuitName)
	if !ok {
		return nil, fmt.Errorf("%s circuit not registered", circuitName)
	}

	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness creation: %w", err)
	}

	proof, err := groth16.Prove(cc.CS, cc.ProvingKey, w)
	if err != nil {
		return nil, fmt.Errorf("groth16.Prove: %w", err)
	}

	pubWitness, err := w.Public()
	if err != nil {
		return nil, fmt.Errorf("public witness extraction: %w", err)
	}

	// Self-check: if this fails, we never emit a bad artifact.
	if err := groth16.Verify(proof, cc.VerifyingKey, pubWitness); err != nil {
		return nil, fmt.Errorf("self-verify: %w", err)
	}

	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		return nil, fmt.Errorf("serialize proof: %w", err)
	}

	var pubBuf bytes.Buffer
	if _, err := pubWitness.WriteTo(&pubBuf); err != nil {
		return nil, fmt.Errorf("serialize public witness: %w", err)
	}

	pubInputs, err := decodePublicInputsBN254(&pubBuf)
	if err != nil {
		return nil, fmt.Errorf("decode public inputs: %w", err)
	}

	return &TallyProofArtifact{
		ProofBytes:         proofBuf.Bytes(),
		PublicWitnessBytes: pubBuf.Bytes(),
		PublicInputs:       pubInputs,
	}, nil
}

// VerifyTallyProofBytes re-verifies a serialized tally proof using the
// circuit's compiled verifying key. Kept as a 16-slot-default wrapper
// for back-compat; prefer VerifyTallyBytes with an explicit circuit name.
func VerifyTallyProofBytes(p *Prover, proofBytes, pubWitnessBytes []byte) error {
	return VerifyTallyBytes(p, "tallyProof", proofBytes, pubWitnessBytes)
}

// VerifyTallyBytes verifies a serialized tally proof for any sized
// circuit (tallyProof_16, tallyProof_64, tallyProof_256, or the legacy
// "tallyProof" alias).
func VerifyTallyBytes(p *Prover, circuitName string, proofBytes, pubWitnessBytes []byte) error {
	cc, ok := p.GetCircuit(circuitName)
	if !ok {
		return fmt.Errorf("%s circuit not registered", circuitName)
	}

	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("read proof: %w", err)
	}

	pw, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("alloc public witness: %w", err)
	}
	if _, err := pw.ReadFrom(bytes.NewReader(pubWitnessBytes)); err != nil {
		return fmt.Errorf("read public witness: %w", err)
	}

	return groth16.Verify(proof, cc.VerifyingKey, pw)
}

// decodePublicInputsBN254 parses a gnark-serialized public witness into
// 0x-prefixed hex field elements. The witness wire format for BN254 is:
// 12-byte header (curve id, nbPublic, nbSecret) followed by 32-byte BE
// field elements.
func decodePublicInputsBN254(buf *bytes.Buffer) ([]string, error) {
	data := buf.Bytes()
	const headerSize = 12
	const elementSize = 32

	if len(data) < headerSize {
		return nil, fmt.Errorf("public witness too short: %d bytes", len(data))
	}

	body := data[headerSize:]
	if len(body)%elementSize != 0 {
		return nil, fmt.Errorf("public witness body not aligned: %d bytes", len(body))
	}

	n := len(body) / elementSize
	out := make([]string, n)
	for i := 0; i < n; i++ {
		v := new(big.Int).SetBytes(body[i*elementSize : (i+1)*elementSize])
		out[i] = fmt.Sprintf("0x%x", v)
	}
	return out, nil
}
