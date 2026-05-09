package prover

import (
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// TestNativeLoadsWasmKeys reads keys produced by the WASM exporter
// (public/v3_wasm_export_diag.mjs) and tries to use them natively for
// Prove + Verify against a constructed mint witness.
//
// The point: validates the inverse direction of issue #3 — wasm32 → amd64 — so
// we know whether a build pipeline that compiles keys in WASM and ships them
// to both sides is viable. If this passes, native Go is happy with
// wasm-flavored bytes and a single set of keys serves all clients.
//
// Run after: node public/v3_wasm_export_diag.mjs mint
//
//	go test -run TestNativeLoadsWasmKeys -v ./prover
func TestNativeLoadsWasmKeys(t *testing.T) {
	csPath := "/tmp/wasm-keys-mint.cs"
	pkPath := "/tmp/wasm-keys-mint.pk"
	vkPath := "/tmp/wasm-keys-mint.vk"
	for _, p := range []string{csPath, pkPath, vkPath} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("missing %s — run `node public/v3_wasm_export_diag.mjs mint` first", p)
		}
	}

	cs := groth16.NewCS(ecc.BN254)
	{
		f, err := os.Open(csPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cs.ReadFrom(f); err != nil {
			f.Close()
			t.Fatalf("cs ReadFrom: %v", err)
		}
		f.Close()
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	{
		f, err := os.Open(pkPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pk.ReadFrom(f); err != nil {
			f.Close()
			t.Fatalf("pk ReadFrom: %v", err)
		}
		f.Close()
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	{
		f, err := os.Open(vkPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := vk.ReadFrom(f); err != nil {
			f.Close()
			t.Fatalf("vk ReadFrom: %v", err)
		}
		f.Close()
	}

	t.Logf("loaded wasm-flavored keys: cs.constraints=%d", cs.GetNbConstraints())

	// Build a satisfying mint witness. Caller==Minter, postStateRoot is a
	// computed MiMC hash; use mint helper from prover_test.go logic.
	// MintCircuit fields: PreStateRoot, PostStateRoot, Caller, To, Amount, Minter, BalanceTo
	// Constraint: caller == minter, postStateRoot == MiMC(to, balanceTo+amount)
	postRoot := MiMCHashBigInt(big.NewInt(99), big.NewInt(1500))
	assignment := &MintCircuit{
		PreStateRoot:  0,
		PostStateRoot: postRoot,
		Caller:        42,
		To:            99,
		Amount:        1000,
		Minter:        42,
		BalanceTo:     500,
	}
	wit, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	csIface, ok := cs.(constraint.ConstraintSystem)
	if !ok {
		t.Fatalf("cs not ConstraintSystem: %T", cs)
	}
	proof, err := groth16.Prove(csIface, pk, wit)
	if err != nil {
		t.Fatalf("native Prove with wasm-flavored keys: %v", err)
	}
	pubW, _ := wit.Public()
	if err := groth16.Verify(proof, vk, pubW); err != nil {
		t.Fatalf("native Verify with wasm-flavored keys: %v", err)
	}
	t.Log("native Prove + Verify with wasm-compiled keys: OK")
}
