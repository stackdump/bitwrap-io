package prover

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// loadedAndProveOK is the inner workhorse for TestLoadKeysOnlyProveSubprocess.
// Loads cs/pk/vk from disk, builds a witness from /tmp/v3-witness-dump.json,
// then proves and verifies. Lives in its own file (no other test imports
// twistededwards directly) so a fresh `go test` of *this package alone*
// doesn't pre-warm gnark-crypto's twisted-Edwards lazy curve-params init
// before this test runs.
func loadedAndProveOK(t *testing.T) {
	const name = "voteCastHomomorphic_8"
	csPath := "/tmp/native-keys-" + name + ".cs"
	pkPath := "/tmp/native-keys-" + name + ".pk"
	vkPath := "/tmp/native-keys-" + name + ".vk"

	cs := groth16.NewCS(ecc.BN254)
	if f, err := os.Open(csPath); err != nil {
		t.Fatal(err)
	} else {
		if _, err := cs.ReadFrom(f); err != nil {
			f.Close()
			t.Fatal(err)
		}
		f.Close()
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if f, err := os.Open(pkPath); err != nil {
		t.Fatal(err)
	} else {
		if _, err := pk.ReadFrom(f); err != nil {
			f.Close()
			t.Fatal(err)
		}
		f.Close()
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if f, err := os.Open(vkPath); err != nil {
		t.Fatal(err)
	} else {
		if _, err := vk.ReadFrom(f); err != nil {
			f.Close()
			t.Fatal(err)
		}
		f.Close()
	}

	dump, err := os.ReadFile("/tmp/v3-witness-dump.json")
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Witness map[string]string `json:"witness"`
	}
	if err := json.Unmarshal(dump, &d); err != nil {
		t.Fatal(err)
	}
	assignment, err := buildVoteCastHomomorphic8Assignment(d.Witness)
	if err != nil {
		t.Fatal(err)
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	csIface := cs.(constraint.ConstraintSystem)
	proof, err := groth16.Prove(csIface, pk, full)
	if err != nil {
		t.Fatalf("prove (subprocess, no prior compile): %v", err)
	}
	pubW, _ := full.Public()
	if err := groth16.Verify(proof, vk, pubW); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
