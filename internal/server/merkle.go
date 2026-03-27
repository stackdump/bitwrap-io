package server

import (
	"math/big"

	"github.com/stackdump/bitwrap-io/prover"
)

const merkleDepth = 20

// computeRegistryRoot builds a MiMC Merkle tree from pre-hashed leaf values
// and returns the root as a decimal string. Matches the JS MerkleTree.fromLeaves()
// algorithm exactly: depth 20, zero-padded, bottom-up.
//
// For efficiency with small voter counts, we use a sparse approach: only hash
// non-zero subtrees. A fully-zero subtree at level L has a known hash (zeroHash[L]).
func computeRegistryRoot(commitments []string) string {
	if len(commitments) == 0 {
		return zeroHashes()[merkleDepth].String()
	}

	zeros := zeroHashes()
	maxLeaves := 1 << merkleDepth

	// Parse leaves
	leaves := make([]*big.Int, maxLeaves)
	for i := 0; i < maxLeaves; i++ {
		if i < len(commitments) {
			leaves[i] = parseBigInt(commitments[i])
		} else {
			leaves[i] = big.NewInt(0) // zeroHashes[0]
		}
	}

	// Build tree bottom-up
	current := leaves
	for level := 0; level < merkleDepth; level++ {
		next := make([]*big.Int, len(current)/2)
		for i := 0; i < len(current); i += 2 {
			// Optimization: if both children are the zero hash at this level,
			// the parent is the zero hash at the next level.
			if current[i].Sign() == 0 && current[i+1].Sign() == 0 && level == 0 {
				next[i/2] = zeros[level+1]
			} else if current[i].Cmp(zeros[level]) == 0 && current[i+1].Cmp(zeros[level]) == 0 {
				next[i/2] = zeros[level+1]
			} else {
				next[i/2] = prover.MiMCHashBigInt(current[i], current[i+1])
			}
		}
		current = next
	}

	return current[0].String()
}

// zeroHashes precomputes the zero hash at each tree level.
// zeroHashes[0] = 0, zeroHashes[i] = mimcHash(zeroHashes[i-1], zeroHashes[i-1])
func zeroHashes() [merkleDepth + 1]*big.Int {
	var zeros [merkleDepth + 1]*big.Int
	zeros[0] = big.NewInt(0)
	for i := 1; i <= merkleDepth; i++ {
		zeros[i] = prover.MiMCHashBigInt(zeros[i-1], zeros[i-1])
	}
	return zeros
}

func parseBigInt(s string) *big.Int {
	n := new(big.Int)
	if len(s) > 2 && s[:2] == "0x" {
		n.SetString(s[2:], 16)
	} else {
		n.SetString(s, 10)
	}
	return n
}
