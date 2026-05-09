package prover

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	gtw "github.com/consensys/gnark/std/algebra/native/twistededwards"
)

// TestPublicInputOrderTallyDecrypt prints the public-witness byte order
// for tallyDecrypt_8 and voteCastHomomorphic_8 so we can confirm
// whether gnark walks (CtA, CtB) as sequential blocks or interleaved.
// The Solidity verifier ingests `input[]` in this exact order; getting
// it wrong is indistinguishable from a proof-validity failure.
func TestPublicInputOrderTallyDecrypt(t *testing.T) {
	// tallyDecrypt_8: PkCreator(2) + A[8](16) + B[8](16) + Tallies[8](8) = 42
	c := &TallyDecryptCircuit_8{}
	c.SkCreator = big.NewInt(0xc0ffee)
	c.PkCreator = gtw.Point{X: big.NewInt(1), Y: big.NewInt(2)}
	for j := 0; j < TallyDecryptChoices; j++ {
		c.A[j] = gtw.Point{X: big.NewInt(int64(100 + j)), Y: big.NewInt(int64(200 + j))}
		c.B[j] = gtw.Point{X: big.NewInt(int64(300 + j)), Y: big.NewInt(int64(400 + j))}
		c.Tallies[j] = j + 1
	}
	wit, err := frontend.NewWitness(c, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := wit.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	// gnark public witness: 4-byte count of public + 4-byte count of secret
	// (zero) + 4-byte total elements + each element as 32 bytes
	t.Logf("tallyDecrypt_8 public witness bytes (first 12 bytes are header):")
	hdr := buf.Bytes()[:12]
	body := buf.Bytes()[12:]
	t.Logf("header: % x", hdr)
	for i := 0; i < len(body)/32; i++ {
		v := new(big.Int).SetBytes(body[i*32 : (i+1)*32])
		t.Logf("  input[%d] = %s", i, v.String())
	}
}

// TestPublicInputOrderVote — same for voteCastHomomorphic_8.
func TestPublicInputOrderVote(t *testing.T) {
	c := &VoteCastHomomorphicCircuit_8{}
	c.PollID = big.NewInt(11)
	c.VoterRegistryRoot = big.NewInt(22)
	c.Nullifier = big.NewInt(33)
	c.MaxChoices = big.NewInt(8)
	c.PkCreator = gtw.Point{X: big.NewInt(1), Y: big.NewInt(2)}
	for j := 0; j < VoteCastHomomorphicChoices; j++ {
		c.CtA[j] = gtw.Point{X: big.NewInt(int64(100 + j)), Y: big.NewInt(int64(200 + j))}
		c.CtB[j] = gtw.Point{X: big.NewInt(int64(300 + j)), Y: big.NewInt(int64(400 + j))}
	}
	for j := 0; j < VoteCastHomomorphicChoices; j++ {
		c.V[j] = 0
		c.R[j] = big.NewInt(0)
	}
	for i := 0; i < homomorphicMerkleDepth; i++ {
		c.PathElements[i] = big.NewInt(0)
		c.PathIndices[i] = big.NewInt(0)
	}
	c.VoterSecret = big.NewInt(0)
	c.VoterWeight = big.NewInt(0)

	wit, err := frontend.NewWitness(c, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := wit.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	body := buf.Bytes()[12:]
	t.Logf("voteCastHomomorphic_8 public witness:")
	for i := 0; i < len(body)/32; i++ {
		v := new(big.Int).SetBytes(body[i*32 : (i+1)*32])
		t.Logf("  input[%d] = %s", i, v.String())
	}
	_ = tedwards.PointAffine{}
}
