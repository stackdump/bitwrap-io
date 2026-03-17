package arc

import (
	"crypto/sha256"
	"encoding/hex"
)

// MerkleTree builds a binary merkle tree from leaf data.
type MerkleTree struct {
	Root   string
	Leaves []string
	Layers [][]string
}

// NewMerkleTree creates a merkle tree from leaf data.
// Each leaf is hashed, then pairs are recursively hashed to form the root.
func NewMerkleTree(data [][]byte) *MerkleTree {
	if len(data) == 0 {
		return &MerkleTree{
			Root:   HashBytes(nil),
			Leaves: nil,
			Layers: nil,
		}
	}

	// Hash all leaves
	leaves := make([]string, len(data))
	for i, d := range data {
		leaves[i] = HashBytes(d)
	}

	// Build tree layers
	layers := [][]string{leaves}
	current := leaves

	for len(current) > 1 {
		next := make([]string, 0, (len(current)+1)/2)

		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				// Hash pair
				next = append(next, HashPair(current[i], current[i+1]))
			} else {
				// Odd node - promote to next level
				next = append(next, current[i])
			}
		}

		layers = append(layers, next)
		current = next
	}

	return &MerkleTree{
		Root:   current[0],
		Leaves: leaves,
		Layers: layers,
	}
}

// NewMerkleTreeFromHashes creates a merkle tree from pre-hashed leaves.
func NewMerkleTreeFromHashes(hashes []string) *MerkleTree {
	if len(hashes) == 0 {
		return &MerkleTree{
			Root:   HashBytes(nil),
			Leaves: nil,
			Layers: nil,
		}
	}

	// Build tree layers
	layers := [][]string{hashes}
	current := hashes

	for len(current) > 1 {
		next := make([]string, 0, (len(current)+1)/2)

		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				next = append(next, HashPair(current[i], current[i+1]))
			} else {
				next = append(next, current[i])
			}
		}

		layers = append(layers, next)
		current = next
	}

	return &MerkleTree{
		Root:   current[0],
		Leaves: hashes,
		Layers: layers,
	}
}

// GetProof returns the merkle proof for a leaf at the given index.
func (t *MerkleTree) GetProof(index int) []ProofNode {
	if index < 0 || index >= len(t.Leaves) {
		return nil
	}

	proof := make([]ProofNode, 0, len(t.Layers)-1)
	idx := index

	for i := 0; i < len(t.Layers)-1; i++ {
		layer := t.Layers[i]
		isLeft := idx%2 == 0
		siblingIdx := idx + 1
		if !isLeft {
			siblingIdx = idx - 1
		}

		if siblingIdx < len(layer) {
			proof = append(proof, ProofNode{
				Hash:   layer[siblingIdx],
				IsLeft: !isLeft,
			})
		}

		idx = idx / 2
	}

	return proof
}

// ProofNode represents a node in a merkle proof.
type ProofNode struct {
	Hash   string `json:"hash"`
	IsLeft bool   `json:"is_left"`
}

// VerifyProof verifies a merkle proof for a given leaf hash.
func VerifyProof(leafHash, root string, proof []ProofNode) bool {
	current := leafHash

	for _, node := range proof {
		if node.IsLeft {
			current = HashPair(node.Hash, current)
		} else {
			current = HashPair(current, node.Hash)
		}
	}

	return current == root
}

// HashBytes returns the SHA256 hash of data as a hex string.
func HashBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// HashPair hashes two hex-encoded hashes together.
func HashPair(left, right string) string {
	combined := left + right
	return HashBytes([]byte(combined))
}

// HashString returns the SHA256 hash of a string.
func HashString(s string) string {
	return HashBytes([]byte(s))
}
