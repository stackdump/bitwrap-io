// MiMC-BN254 Merkle tree — fixed-depth binary tree
// Matches gnark circuit Merkle proof verification exactly

import { mimcHash } from './mimc.js';

// Precompute zero hashes for each level of the tree.
// zeroHashes[0] = 0 (empty leaf)
// zeroHashes[i] = mimcHash(zeroHashes[i-1], zeroHashes[i-1])
function computeZeroHashes(depth) {
  const zeros = new Array(depth + 1);
  zeros[0] = 0n;
  for (let i = 1; i <= depth; i++) {
    zeros[i] = mimcHash(zeros[i - 1], zeros[i - 1]);
  }
  return zeros;
}

export class MerkleTree {
  constructor(root, leaves, depth, layers) {
    this.root = root;
    this.leaves = leaves;
    this.depth = depth;
    this.layers = layers;
  }

  // Build a fixed-depth Merkle tree from leaf values (BigInt field elements).
  // Leaves are hashed as mimcHash(key, value) before insertion.
  // If fewer leaves than 2^depth, remaining slots are padded with zero hashes.
  static fromEntries(entries, depth = 20) {
    const maxLeaves = 1 << depth;
    if (entries.length > maxLeaves) {
      throw new Error(`Too many entries: ${entries.length} > ${maxLeaves}`);
    }

    const zeroHashes = computeZeroHashes(depth);

    // Hash entries into leaves: mimcHash(key, value)
    const leafHashes = entries.map(([key, value]) => mimcHash(key, value));

    // Pad with zero leaf hashes
    while (leafHashes.length < maxLeaves) {
      leafHashes.push(zeroHashes[0]);
    }

    // Build tree bottom-up
    const layers = [leafHashes];
    let current = leafHashes;

    for (let level = 0; level < depth; level++) {
      const next = [];
      for (let i = 0; i < current.length; i += 2) {
        next.push(mimcHash(current[i], current[i + 1]));
      }
      layers.push(next);
      current = next;
    }

    return new MerkleTree(current[0], leafHashes, depth, layers);
  }

  // Build from pre-hashed leaves (BigInt values already hashed)
  static fromLeaves(leaves, depth = 20) {
    const maxLeaves = 1 << depth;
    if (leaves.length > maxLeaves) {
      throw new Error(`Too many leaves: ${leaves.length} > ${maxLeaves}`);
    }

    const zeroHashes = computeZeroHashes(depth);

    // Pad with zero hashes
    const padded = [...leaves];
    while (padded.length < maxLeaves) {
      padded.push(zeroHashes[0]);
    }

    const layers = [padded];
    let current = padded;

    for (let level = 0; level < depth; level++) {
      const next = [];
      for (let i = 0; i < current.length; i += 2) {
        next.push(mimcHash(current[i], current[i + 1]));
      }
      layers.push(next);
      current = next;
    }

    return new MerkleTree(current[0], padded, depth, layers);
  }

  // Get Merkle proof for leaf at index.
  // Returns { pathElements: BigInt[], pathIndices: number[] }
  // pathIndices[i] = 0 means leaf is on left, sibling on right
  // pathIndices[i] = 1 means leaf is on right, sibling on left
  // This matches the gnark circuit's Select logic exactly.
  getProof(index) {
    if (index < 0 || index >= this.leaves.length) {
      throw new Error(`Index out of range: ${index}`);
    }

    const pathElements = [];
    const pathIndices = [];
    let idx = index;

    for (let level = 0; level < this.depth; level++) {
      const isRight = idx % 2 === 1;
      const siblingIdx = isRight ? idx - 1 : idx + 1;

      pathElements.push(this.layers[level][siblingIdx]);
      pathIndices.push(isRight ? 1 : 0);

      idx = Math.floor(idx / 2);
    }

    return { pathElements, pathIndices };
  }

  // Update a leaf and recompute the tree
  updateLeaf(index, newLeafHash) {
    if (index < 0 || index >= this.leaves.length) {
      throw new Error(`Index out of range: ${index}`);
    }

    this.layers[0][index] = newLeafHash;
    let idx = index;

    for (let level = 0; level < this.depth; level++) {
      const pairIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      const parentIdx = Math.floor(idx / 2);
      const left = idx % 2 === 0 ? this.layers[level][idx] : this.layers[level][pairIdx];
      const right = idx % 2 === 0 ? this.layers[level][pairIdx] : this.layers[level][idx];
      this.layers[level + 1][parentIdx] = mimcHash(left, right);
      idx = parentIdx;
    }

    this.root = this.layers[this.depth][0];
    this.leaves = this.layers[0];
  }

  // Verify a Merkle proof
  static verifyProof(leafHash, root, pathElements, pathIndices) {
    let current = leafHash;
    for (let i = 0; i < pathElements.length; i++) {
      if (pathIndices[i] === 1) {
        // Leaf is on right: hash(sibling, current)
        current = mimcHash(pathElements[i], current);
      } else {
        // Leaf is on left: hash(current, sibling)
        current = mimcHash(current, pathElements[i]);
      }
    }
    return current === root;
  }
}
