package prover

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	gtw "github.com/consensys/gnark/std/algebra/native/twistededwards"
)

// TestV3ProofByteLayout dumps the byte-level layout of v3 Groth16 proofs
// to determine whether they carry commitment data beyond the canonical
// (A, B, C) layout. If the proof is >8 field elements (256 bytes raw,
// or 128 bytes compressed), gnark has appended commitment scheme data
// that the auto-generated Solidity verifier — which only accepts 8
// elements — can't ingest. That would be the root cause of issue #6.
func TestV3ProofByteLayout(t *testing.T) {
	cases := []struct {
		name    string
		schema  frontend.Circuit
		assign  func(t *testing.T) frontend.Circuit
	}{
		{
			"voteCastHomomorphic_8",
			&VoteCastHomomorphicCircuit_8{},
			func(t *testing.T) frontend.Circuit { return synthV3VoteAssignment(t) },
		},
		{
			"tallyDecrypt_8",
			&TallyDecryptCircuit_8{},
			func(t *testing.T) frontend.Circuit { return synthV3TallyAssignment(t) },
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := NewProver()
			cc, err := p.CompileCircuit(c.name, c.schema)
			if err != nil {
				t.Fatal(err)
			}

			wit, err := frontend.NewWitness(c.assign(t), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			proof, err := groth16.Prove(cc.CS, cc.ProvingKey, wit)
			if err != nil {
				t.Fatal(err)
			}

			var compressed bytes.Buffer
			if _, err := proof.WriteTo(&compressed); err != nil {
				t.Fatal(err)
			}
			var raw bytes.Buffer
			if _, err := proof.WriteRawTo(&raw); err != nil {
				t.Fatal(err)
			}
			t.Logf("circuit=%s constraints=%d compressed=%dB raw=%dB",
				c.name, cc.Constraints, compressed.Len(), raw.Len())
			t.Logf("  raw expected for plain Groth16: 8 × 32 = 256 bytes")
			t.Logf("  raw observed: %d bytes → %d field elements",
				raw.Len(), raw.Len()/32)
			if raw.Len() > 256 {
				t.Logf("  EXTRA: %d bytes (%d field elements) — commitment scheme data",
					raw.Len()-256, (raw.Len()-256)/32)
			}
		})
	}
}

func synthV3VoteAssignment(t *testing.T) *VoteCastHomomorphicCircuit_8 {
	t.Helper()
	c := &VoteCastHomomorphicCircuit_8{}
	c.PollID = big.NewInt(42)
	c.MaxChoices = 3
	c.VoterSecret = big.NewInt(100)
	c.VoterWeight = big.NewInt(1)

	leaf := MiMCHashBigInt(big.NewInt(100), big.NewInt(1))
	current := leaf
	zero := big.NewInt(0)
	for i := 0; i < homomorphicMerkleDepth; i++ {
		c.PathElements[i] = zero
		c.PathIndices[i] = 0
		current = MiMCHashBigInt(current, zero)
	}
	c.VoterRegistryRoot = current
	c.Nullifier = MiMCHashBigInt(big.NewInt(100), big.NewInt(42))

	g := PedersenG()
	sk := big.NewInt(0xc0ffee)
	var pk tedwards.PointAffine
	pk.ScalarMultiplication(&g, sk)
	c.PkCreator = ptVar(&pk)

	for j := 0; j < VoteCastHomomorphicChoices; j++ {
		var v int64
		if j == 1 {
			v = 1
		}
		r := big.NewInt(int64(1000 + j))
		ct := Encrypt(big.NewInt(v), r, &pk)
		c.V[j] = v
		c.R[j] = r
		c.CtA[j] = ptVar(&ct.A)
		c.CtB[j] = ptVar(&ct.B)
	}
	return c
}

func synthV3TallyAssignment(t *testing.T) *TallyDecryptCircuit_8 {
	t.Helper()
	g := PedersenG()
	sk := big.NewInt(0xc0ffee)
	var pk tedwards.PointAffine
	pk.ScalarMultiplication(&g, sk)

	c := &TallyDecryptCircuit_8{}
	c.SkCreator = sk
	c.PkCreator = ptVar(&pk)
	r := big.NewInt(7)
	ct := Encrypt(big.NewInt(0), r, &pk)
	for j := 0; j < TallyDecryptChoices; j++ {
		c.A[j] = ptVar(&ct.A)
		c.B[j] = ptVar(&ct.B)
		c.Tallies[j] = 0
	}
	return c
}

func ptVar(p *tedwards.PointAffine) gtw.Point {
	var x, y big.Int
	p.X.BigInt(&x)
	p.Y.BigInt(&y)
	return gtw.Point{X: &x, Y: &y}
}
