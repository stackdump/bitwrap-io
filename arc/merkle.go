package arc

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

// MiMCHash computes MiMC hash of two field elements.
// Matches the gnark circuit's mimcHash(left, right) exactly:
//
//	h.Write(left); h.Write(right); return h.Sum()
func MiMCHash(left, right *fr.Element) fr.Element {
	h := mimc.NewMiMC()
	lb := left.Bytes()
	rb := right.Bytes()
	h.Write(lb[:])
	h.Write(rb[:])
	sum := h.Sum(nil)
	var result fr.Element
	result.SetBytes(sum)
	return result
}

// MiMCHashInts computes MiMC hash of two int64 values.
func MiMCHashInts(a, b int64) fr.Element {
	var fa, fb fr.Element
	fa.SetInt64(a)
	fb.SetInt64(b)
	return MiMCHash(&fa, &fb)
}

// MerkleTree is a fixed-depth binary Merkle tree using MiMC-BN254.
type MerkleTree struct {
	Root   fr.Element
	Leaves []fr.Element
	Depth  int
	Layers [][]fr.Element
}

// ProofNode represents a sibling in a Merkle proof.
type ProofNode struct {
	Element fr.Element `json:"element"`
	// Index: 0 means the leaf is on the left, 1 means the leaf is on the right.
	// Matches gnark circuit PathIndices semantics.
	Index int `json:"index"`
}

// NewMerkleTree builds a fixed-depth binary Merkle tree from leaf hashes.
// Pads with zero hashes if fewer leaves than 2^depth.
func NewMerkleTree(leaves []fr.Element, depth int) *MerkleTree {
	maxLeaves := 1 << depth

	// Pad with zeros
	padded := make([]fr.Element, maxLeaves)
	copy(padded, leaves)
	// Remaining elements are zero-valued (fr.Element{} == 0)

	layers := make([][]fr.Element, depth+1)
	layers[0] = padded
	current := padded

	for level := 0; level < depth; level++ {
		next := make([]fr.Element, len(current)/2)
		for i := 0; i < len(current); i += 2 {
			next[i/2] = MiMCHash(&current[i], &current[i+1])
		}
		layers[level+1] = next
		current = next
	}

	return &MerkleTree{
		Root:   current[0],
		Leaves: padded,
		Depth:  depth,
		Layers: layers,
	}
}

// NewMerkleTreeFromEntries builds a tree from (key, value) pairs.
// Each leaf is mimcHash(key, value).
func NewMerkleTreeFromEntries(entries [][2]fr.Element, depth int) *MerkleTree {
	leaves := make([]fr.Element, len(entries))
	for i, entry := range entries {
		leaves[i] = MiMCHash(&entry[0], &entry[1])
	}
	return NewMerkleTree(leaves, depth)
}

// GetProof returns the Merkle proof for a leaf at the given index.
func (t *MerkleTree) GetProof(index int) []ProofNode {
	if index < 0 || index >= len(t.Leaves) {
		return nil
	}

	proof := make([]ProofNode, t.Depth)
	idx := index

	for level := 0; level < t.Depth; level++ {
		isRight := idx%2 == 1
		siblingIdx := idx + 1
		pathIndex := 0
		if isRight {
			siblingIdx = idx - 1
			pathIndex = 1
		}

		proof[level] = ProofNode{
			Element: t.Layers[level][siblingIdx],
			Index:   pathIndex,
		}

		idx = idx / 2
	}

	return proof
}

// VerifyProof verifies a Merkle proof for a given leaf hash.
func VerifyProof(leafHash, root fr.Element, proof []ProofNode) bool {
	current := leafHash

	for _, node := range proof {
		if node.Index == 1 {
			// Leaf is on right: hash(sibling, current)
			current = MiMCHash(&node.Element, &current)
		} else {
			// Leaf is on left: hash(current, sibling)
			current = MiMCHash(&current, &node.Element)
		}
	}

	return current.Equal(&root)
}

// ElementFromInt64 creates a field element from an int64.
func ElementFromInt64(v int64) fr.Element {
	var e fr.Element
	e.SetInt64(v)
	return e
}

// ElementFromBigInt creates a field element from a *big.Int.
func ElementFromBigInt(v *big.Int) fr.Element {
	var e fr.Element
	e.SetBigInt(v)
	return e
}
