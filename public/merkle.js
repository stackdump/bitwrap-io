// MiMC-BN254 Merkle tree — fixed-depth binary tree (sparse representation).
// Matches gnark circuit Merkle proof verification exactly.
//
// Sparse: only nodes on the path from a non-empty leaf to the root are stored.
// For empty subtrees we use precomputed zero hashes. Cost is O(N*depth) instead
// of O(2^depth) — voting with depth=20 was hanging the browser because the
// dense version did ~2M mimcHash calls for a 1-leaf tree.

import { mimcHash } from './mimc.js';

// Precompute zero hashes for each level: zeros[i] = mimcHash(zeros[i-1], zeros[i-1]).
function computeZeroHashes(depth) {
  const zeros = new Array(depth + 1);
  zeros[0] = 0n;
  for (let i = 1; i <= depth; i++) {
    zeros[i] = mimcHash(zeros[i - 1], zeros[i - 1]);
  }
  return zeros;
}

function buildSparseLayers(leafMap, depth, zeros) {
  // layers[level] is a Map<index, hash>. Indices not present use zeros[level].
  const layers = [leafMap];
  for (let level = 0; level < depth; level++) {
    const cur = layers[level];
    const next = new Map();
    const parents = new Set();
    for (const idx of cur.keys()) parents.add(Math.floor(idx / 2));
    for (const p of parents) {
      const li = p * 2, ri = li + 1;
      const left = cur.has(li) ? cur.get(li) : zeros[level];
      const right = cur.has(ri) ? cur.get(ri) : zeros[level];
      next.set(p, mimcHash(left, right));
    }
    layers.push(next);
  }
  return layers;
}

export class MerkleTree {
  constructor(depth, leaves, leafMap, layers, zeros) {
    this.depth = depth;
    this.leaves = leaves;       // dense array of original leaf hashes at indices 0..N-1
    this.leafMap = leafMap;     // Map<index, hash> — same data, sparse index
    this.layers = layers;       // layers[level] = Map<index, hash>
    this.zeroHashes = zeros;
    this.root = layers[depth].get(0) ?? zeros[depth];
  }

  // Build from pre-hashed leaves (BigInt field elements at indices 0..leaves.length-1).
  static fromLeaves(leaves, depth = 20) {
    const maxLeaves = 1n << BigInt(depth);
    if (BigInt(leaves.length) > maxLeaves) {
      throw new Error(`Too many leaves: ${leaves.length} > ${maxLeaves}`);
    }
    const zeros = computeZeroHashes(depth);
    const leafMap = new Map();
    leaves.forEach((leaf, i) => leafMap.set(i, leaf));
    const layers = buildSparseLayers(new Map(leafMap), depth, zeros);
    return new MerkleTree(depth, [...leaves], leafMap, layers, zeros);
  }

  // Build from [key, value] entries — hashed as mimcHash(key, value) into leaves.
  static fromEntries(entries, depth = 20) {
    const hashed = entries.map(([k, v]) => mimcHash(k, v));
    return MerkleTree.fromLeaves(hashed, depth);
  }

  // Merkle proof for leaf at index.
  // pathIndices[i] = 0 → leaf is on left, sibling on right. Matches gnark Select logic.
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
      const layer = this.layers[level];
      const sibling = layer.has(siblingIdx) ? layer.get(siblingIdx) : this.zeroHashes[level];
      pathElements.push(sibling);
      pathIndices.push(isRight ? 1 : 0);
      idx = Math.floor(idx / 2);
    }
    return { pathElements, pathIndices };
  }

  // Update leaf at index and recompute only the path to root.
  updateLeaf(index, newLeafHash) {
    if (index < 0) throw new Error(`Index out of range: ${index}`);
    this.layers[0].set(index, newLeafHash);
    if (index < this.leaves.length) this.leaves[index] = newLeafHash;
    else {
      // extend dense leaves with zero padding if caller adds beyond current length
      while (this.leaves.length < index) this.leaves.push(0n);
      this.leaves.push(newLeafHash);
    }
    this.leafMap.set(index, newLeafHash);

    let idx = index;
    for (let level = 0; level < this.depth; level++) {
      const li = (idx % 2 === 0) ? idx : idx - 1;
      const ri = li + 1;
      const layer = this.layers[level];
      const left = layer.has(li) ? layer.get(li) : this.zeroHashes[level];
      const right = layer.has(ri) ? layer.get(ri) : this.zeroHashes[level];
      const parentIdx = Math.floor(idx / 2);
      this.layers[level + 1].set(parentIdx, mimcHash(left, right));
      idx = parentIdx;
    }
    this.root = this.layers[this.depth].get(0) ?? this.zeroHashes[this.depth];
  }

  // Verify a Merkle proof against a root.
  static verifyProof(leafHash, root, pathElements, pathIndices) {
    let current = leafHash;
    for (let i = 0; i < pathElements.length; i++) {
      if (pathIndices[i] === 1) {
        current = mimcHash(pathElements[i], current);
      } else {
        current = mimcHash(current, pathElements[i]);
      }
    }
    return current === root;
  }
}
