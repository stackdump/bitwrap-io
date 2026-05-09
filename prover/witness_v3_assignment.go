package prover

import (
	"fmt"

	goprover "github.com/pflow-xyz/go-pflow/prover"
	"github.com/consensys/gnark/frontend"
	gtw "github.com/consensys/gnark/std/algebra/native/twistededwards"
)

// buildVoteCastHomomorphic8Assignment converts a JS-side witness map
// into a populated VoteCastHomomorphicCircuit_8. Field names mirror
// what public/witness-builder.js emits in
// buildVoteCastHomomorphicWitness — keep both sides in lockstep.
func buildVoteCastHomomorphic8Assignment(witness map[string]string) (frontend.Circuit, error) {
	c := &VoteCastHomomorphicCircuit_8{}

	mustField := func(key string, dst *frontend.Variable) error {
		v, err := goprover.ParseWitnessField(witness, key)
		if err != nil {
			return err
		}
		*dst = v
		return nil
	}
	mustPoint := func(prefix string, dst *gtw.Point) error {
		x, err := goprover.ParseWitnessField(witness, prefix+".X")
		if err != nil {
			return err
		}
		y, err := goprover.ParseWitnessField(witness, prefix+".Y")
		if err != nil {
			return err
		}
		dst.X = x
		dst.Y = y
		return nil
	}

	for _, f := range []struct {
		key string
		dst *frontend.Variable
	}{
		{"pollId", &c.PollID},
		{"voterRegistryRoot", &c.VoterRegistryRoot},
		{"nullifier", &c.Nullifier},
		{"maxChoices", &c.MaxChoices},
		{"voterSecret", &c.VoterSecret},
		{"voterWeight", &c.VoterWeight},
	} {
		if err := mustField(f.key, f.dst); err != nil {
			return nil, fmt.Errorf("voteCastHomomorphic_8 witness %s: %w", f.key, err)
		}
	}
	if err := mustPoint("pkCreator", &c.PkCreator); err != nil {
		return nil, fmt.Errorf("voteCastHomomorphic_8 witness pkCreator: %w", err)
	}
	for j := 0; j < VoteCastHomomorphicChoices; j++ {
		if err := mustField(fmt.Sprintf("V%d", j), &c.V[j]); err != nil {
			return nil, err
		}
		if err := mustField(fmt.Sprintf("R%d", j), &c.R[j]); err != nil {
			return nil, err
		}
		if err := mustPoint(fmt.Sprintf("CtA%d", j), &c.CtA[j]); err != nil {
			return nil, err
		}
		if err := mustPoint(fmt.Sprintf("CtB%d", j), &c.CtB[j]); err != nil {
			return nil, err
		}
	}
	for i := 0; i < homomorphicMerkleDepth; i++ {
		if err := mustField(fmt.Sprintf("pathElement%d", i), &c.PathElements[i]); err != nil {
			return nil, err
		}
		if err := mustField(fmt.Sprintf("pathIndex%d", i), &c.PathIndices[i]); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// buildTallyDecrypt8Assignment converts a JS-side witness map into a
// populated TallyDecryptCircuit_8.
func buildTallyDecrypt8Assignment(witness map[string]string) (frontend.Circuit, error) {
	c := &TallyDecryptCircuit_8{}

	sk, err := goprover.ParseWitnessField(witness, "skCreator")
	if err != nil {
		return nil, fmt.Errorf("tallyDecrypt_8 witness skCreator: %w", err)
	}
	c.SkCreator = sk

	pkX, err := goprover.ParseWitnessField(witness, "pkCreator.X")
	if err != nil {
		return nil, err
	}
	pkY, err := goprover.ParseWitnessField(witness, "pkCreator.Y")
	if err != nil {
		return nil, err
	}
	c.PkCreator = gtw.Point{X: pkX, Y: pkY}

	for j := 0; j < TallyDecryptChoices; j++ {
		ax, err := goprover.ParseWitnessField(witness, fmt.Sprintf("A%d.X", j))
		if err != nil {
			return nil, err
		}
		ay, err := goprover.ParseWitnessField(witness, fmt.Sprintf("A%d.Y", j))
		if err != nil {
			return nil, err
		}
		c.A[j] = gtw.Point{X: ax, Y: ay}

		bx, err := goprover.ParseWitnessField(witness, fmt.Sprintf("B%d.X", j))
		if err != nil {
			return nil, err
		}
		by, err := goprover.ParseWitnessField(witness, fmt.Sprintf("B%d.Y", j))
		if err != nil {
			return nil, err
		}
		c.B[j] = gtw.Point{X: bx, Y: by}

		t, err := goprover.ParseWitnessField(witness, fmt.Sprintf("Tallies%d", j))
		if err != nil {
			return nil, err
		}
		c.Tallies[j] = t
	}
	return c, nil
}
