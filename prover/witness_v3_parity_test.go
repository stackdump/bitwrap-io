package prover

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	gtw "github.com/consensys/gnark/std/algebra/native/twistededwards"
)

// TestWitnessV3Parity runs the JS witness builder, ingests its output,
// builds the matching gnark assignment, and runs Prove + Verify on
// both v3 circuits. This is the contract between
// public/witness-builder.js and prover/{vote,tally}_*_gen.go: any
// drift in field naming, ordering, or value derivation surfaces here
// before it gets shipped to a browser.
//
// Skipped if `node` is unavailable.
func TestWitnessV3Parity(t *testing.T) {
	if testing.Short() {
		t.Skip("v3 witness parity test compiles two large circuits; skip in short mode")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed; skipping JS witness parity test")
	}

	root := findRepoRoot(t)
	cmd := exec.Command("node", "public/witness_v3_parity.mjs")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("node script failed: %v\n%s", err, stderr)
	}

	var dump struct {
		PollID      string `json:"pollId"`
		VoterSecret string `json:"voterSecret"`
		VoterWeight string `json:"voterWeight"`
		Choice      int    `json:"choice"`
		MaxChoices  int    `json:"maxChoices"`
		SkCreator   string `json:"skCreator"`
		PkCreator   string `json:"pkCreator"`

		VoteCastHomomorphic struct {
			Circuit string `json:"circuit"`
			Witness map[string]string `json:"witness"`
		} `json:"voteCastHomomorphic"`

		TallyDecrypt struct {
			Circuit string `json:"circuit"`
			Witness map[string]string `json:"witness"`
			Tallies []int  `json:"tallies"`
		} `json:"tallyDecrypt"`
	}
	if err := json.Unmarshal(out, &dump); err != nil {
		t.Fatalf("decode JS output: %v\nraw: %s", err, string(out))
	}

	t.Run("voteCastHomomorphic_8", func(t *testing.T) {
		assertVoteCastHomomorphicWitness(t, dump.VoteCastHomomorphic.Witness)
	})

	t.Run("tallyDecrypt_8", func(t *testing.T) {
		if len(dump.TallyDecrypt.Tallies) != TallyDecryptChoices {
			t.Fatalf("expected %d tallies, got %d", TallyDecryptChoices, len(dump.TallyDecrypt.Tallies))
		}
		assertTallyDecryptWitness(t, dump.TallyDecrypt.Witness)
	})

	// Optional: leave the dump on disk for manual debugging.
	_ = os.WriteFile(filepath.Join(t.TempDir(), "v3-witness.json"), out, 0o644)
}

func assertVoteCastHomomorphicWitness(t *testing.T, w map[string]string) {
	t.Helper()
	c := &VoteCastHomomorphicCircuit_8{}
	c.PollID = mustField(t, w, "pollId")
	c.VoterRegistryRoot = mustField(t, w, "voterRegistryRoot")
	c.Nullifier = mustField(t, w, "nullifier")
	c.MaxChoices = mustField(t, w, "maxChoices")
	c.PkCreator = pointFromMap(t, w, "pkCreator")
	c.VoterSecret = mustField(t, w, "voterSecret")
	c.VoterWeight = mustField(t, w, "voterWeight")

	for j := 0; j < VoteCastHomomorphicChoices; j++ {
		c.V[j] = mustField(t, w, fmtIdx("V", j))
		c.R[j] = mustField(t, w, fmtIdx("R", j))
		c.CtA[j] = pointFromMap(t, w, fmtIdx("CtA", j))
		c.CtB[j] = pointFromMap(t, w, fmtIdx("CtB", j))
	}
	for i := 0; i < homomorphicMerkleDepth; i++ {
		c.PathElements[i] = mustField(t, w, fmtIdx("pathElement", i))
		c.PathIndices[i] = mustField(t, w, fmtIdx("pathIndex", i))
	}

	proveAndVerify(t, "voteCastHomomorphic_8", &VoteCastHomomorphicCircuit_8{}, c)
}

func assertTallyDecryptWitness(t *testing.T, w map[string]string) {
	t.Helper()
	c := &TallyDecryptCircuit_8{}
	c.PkCreator = pointFromMap(t, w, "pkCreator")
	c.SkCreator = mustField(t, w, "skCreator")
	for j := 0; j < TallyDecryptChoices; j++ {
		c.A[j] = pointFromMap(t, w, fmtIdx("A", j))
		c.B[j] = pointFromMap(t, w, fmtIdx("B", j))
		c.Tallies[j] = mustField(t, w, fmtIdx("Tallies", j))
	}

	proveAndVerify(t, "tallyDecrypt_8", &TallyDecryptCircuit_8{}, c)
}

func proveAndVerify(t *testing.T, name string, schema, assignment frontend.Circuit) {
	t.Helper()
	p := NewProver()
	cc, err := p.CompileCircuit(name, schema)
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness %s: %v", name, err)
	}
	proof, err := groth16.Prove(cc.CS, cc.ProvingKey, full)
	if err != nil {
		t.Fatalf("prove %s: %v", name, err)
	}
	pubW, err := full.Public()
	if err != nil {
		t.Fatalf("public witness %s: %v", name, err)
	}
	if err := groth16.Verify(proof, cc.VerifyingKey, pubW); err != nil {
		t.Fatalf("verify %s: %v", name, err)
	}
}

func mustField(t *testing.T, m map[string]string, key string) *big.Int {
	t.Helper()
	s, ok := m[key]
	if !ok {
		t.Fatalf("witness missing key %q\nkeys: %v", key, mapKeys(m))
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("witness[%q] = %q is not a decimal big.Int", key, s)
	}
	return n
}

func pointFromMap(t *testing.T, m map[string]string, prefix string) gtw.Point {
	t.Helper()
	xKey := prefix + ".X"
	yKey := prefix + ".Y"
	return gtw.Point{
		X: mustField(t, m, xKey),
		Y: mustField(t, m, yKey),
	}
}

func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func fmtIdx(prefix string, i int) string {
	// Avoids fmt.Sprintf overhead in a hot test helper.
	return prefix + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := make([]byte, 0, 4)
	for i > 0 {
		digits = append(digits, byte('0'+i%10))
		i /= 10
	}
	for l, r := 0, len(digits)-1; l < r; l, r = l+1, r-1 {
		digits[l], digits[r] = digits[r], digits[l]
	}
	return string(digits)
}

// confirm helper imports stay in use even when test is skipped.
var (
	_ = hex.EncodeToString
	_ = (*tedwards.PointAffine)(nil)
)
