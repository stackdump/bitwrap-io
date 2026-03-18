package arc

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestMiMCHash(t *testing.T) {
	// Test vectors from gnark-crypto (verified via TestMiMCHashParity)
	tests := []struct {
		a, b int64
		want string
	}{
		{42, 100, "13603062797811675188639909697080538913826685491246923374232736861692843824956"},
		{1, 100, "2108862887778322224540152968033371138921907848559177206190676617530753041980"},
		{2, 200, "12104544101572163940166299184207267496585694752863501697795764603195813619670"},
		{3, 300, "14050062093042685743601673262179176428971353750296441969316735981035391690629"},
	}

	for _, tt := range tests {
		got := MiMCHashInts(tt.a, tt.b)
		var gotBig big.Int
		got.BigInt(&gotBig)
		if gotBig.String() != tt.want {
			t.Errorf("MiMCHash(%d, %d) = %s, want %s", tt.a, tt.b, gotBig.String(), tt.want)
		}
	}
}

func TestMerkleTree(t *testing.T) {
	// Build a tree with 3 entries at depth 2 (4 leaves)
	entries := [][2]fr.Element{
		{ElementFromInt64(1), ElementFromInt64(100)},
		{ElementFromInt64(2), ElementFromInt64(200)},
		{ElementFromInt64(3), ElementFromInt64(300)},
	}

	tree := NewMerkleTreeFromEntries(entries, 2)

	// Verify leaf 0 proof
	leaf0 := MiMCHashInts(1, 100)
	proof0 := tree.GetProof(0)
	if !VerifyProof(leaf0, tree.Root, proof0) {
		t.Error("Proof for leaf 0 failed verification")
	}

	// Verify leaf 1 proof
	leaf1 := MiMCHashInts(2, 200)
	proof1 := tree.GetProof(1)
	if !VerifyProof(leaf1, tree.Root, proof1) {
		t.Error("Proof for leaf 1 failed verification")
	}

	// Verify leaf 2 proof
	leaf2 := MiMCHashInts(3, 300)
	proof2 := tree.GetProof(2)
	if !VerifyProof(leaf2, tree.Root, proof2) {
		t.Error("Proof for leaf 2 failed verification")
	}

	// Print root for JS parity test
	var rootBig big.Int
	tree.Root.BigInt(&rootBig)
	fmt.Printf("Tree root (depth=2, entries=[(1,100),(2,200),(3,300)]): %s\n", rootBig.String())
}

func TestMerkleTreeDepth20(t *testing.T) {
	// Build a depth-20 tree with 2 entries (matching circuit depth)
	entries := [][2]fr.Element{
		{ElementFromInt64(1), ElementFromInt64(100)},
		{ElementFromInt64(2), ElementFromInt64(200)},
	}

	tree := NewMerkleTreeFromEntries(entries, 20)

	// Verify both proofs
	leaf0 := MiMCHashInts(1, 100)
	proof0 := tree.GetProof(0)
	if len(proof0) != 20 {
		t.Errorf("Expected 20 proof elements, got %d", len(proof0))
	}
	if !VerifyProof(leaf0, tree.Root, proof0) {
		t.Error("Proof for leaf 0 failed verification at depth 20")
	}

	leaf1 := MiMCHashInts(2, 200)
	proof1 := tree.GetProof(1)
	if !VerifyProof(leaf1, tree.Root, proof1) {
		t.Error("Proof for leaf 1 failed verification at depth 20")
	}

	// Print root for JS parity
	var rootBig big.Int
	tree.Root.BigInt(&rootBig)
	fmt.Printf("Tree root (depth=20, entries=[(1,100),(2,200)]): %s\n", rootBig.String())

	// Print proof elements for leaf 0 (first 3 levels for JS parity)
	for i := 0; i < 3; i++ {
		var elemBig big.Int
		proof0[i].Element.BigInt(&elemBig)
		fmt.Printf("  proof0[%d]: element=%s, index=%d\n", i, elemBig.String(), proof0[i].Index)
	}
}
