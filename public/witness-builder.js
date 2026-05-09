// Witness builder for bitwrap ZK circuits
// Builds complete witness objects ready to POST to /api/prove

import { mimcHash } from './mimc.js';
import { MerkleTree } from './merkle.js';
import {
  G as PEDERSEN_G,
  encrypt as pedersenEncrypt,
  encodePointHex,
  decodePointHex,
  scalarMulBase,
  scalarMul,
  pointAdd,
  pointNeg,
  ZERO as PEDERSEN_ZERO,
  SUBGROUP_ORDER,
} from './pedersen.js';

// Format a BigInt as a decimal string for Go's ParseWitnessField
function fieldStr(v) {
  return (typeof v === 'bigint' ? v : BigInt(v)).toString(10);
}

// Flatten path elements/indices into witness fields with numbered keys
function flattenProof(proof, depth, prefix = 'pathElement', indexPrefix = 'pathIndex') {
  const fields = {};
  for (let i = 0; i < depth; i++) {
    fields[`${prefix}${i}`] = fieldStr(proof.pathElements[i]);
    fields[`${indexPrefix}${i}`] = fieldStr(BigInt(proof.pathIndices[i]));
  }
  return fields;
}

// Build a transfer witness
// tree: MerkleTree with current balances
// fromIdx: index of sender leaf in tree
// toIdx: index of recipient leaf in tree
// from, to: account identifiers (BigInt)
// amount: transfer amount (BigInt)
// balanceFrom, balanceTo: current balances (BigInt)
export function buildTransferWitness({ tree, fromIdx, from, to, amount, balanceFrom, balanceTo }) {
  from = BigInt(from);
  to = BigInt(to);
  amount = BigInt(amount);
  balanceFrom = BigInt(balanceFrom);
  balanceTo = BigInt(balanceTo);

  // Pre-state root and Merkle proof for sender
  const preStateRoot = tree.root;
  const proof = tree.getProof(fromIdx);

  // Post-state: compute new balances and post-state root
  // Matches circuit: postLeaf = mimcHash(from, balanceFrom - amount)
  //                  postLeaf2 = mimcHash(to, balanceTo + amount)
  //                  postRoot = mimcHash(postLeaf, postLeaf2)
  const newBalanceFrom = balanceFrom - amount;
  const newBalanceTo = balanceTo + amount;
  const postLeaf = mimcHash(from, newBalanceFrom);
  const postLeaf2 = mimcHash(to, newBalanceTo);
  const postStateRoot = mimcHash(postLeaf, postLeaf2);

  return {
    circuit: 'transfer',
    witness: {
      preStateRoot: fieldStr(preStateRoot),
      postStateRoot: fieldStr(postStateRoot),
      from: fieldStr(from),
      to: fieldStr(to),
      amount: fieldStr(amount),
      balanceFrom: fieldStr(balanceFrom),
      balanceTo: fieldStr(balanceTo),
      ...flattenProof(proof, 20),
    }
  };
}

// Build a mint witness
export function buildMintWitness({ caller, minter, to, amount, balanceTo }) {
  caller = BigInt(caller);
  minter = BigInt(minter);
  to = BigInt(to);
  amount = BigInt(amount);
  balanceTo = BigInt(balanceTo);

  // Mint has simplified state roots (no Merkle tree)
  // postLeaf = mimcHash(to, balanceTo + amount)
  const newBalance = balanceTo + amount;
  const postStateRoot = mimcHash(to, newBalance);

  return {
    circuit: 'mint',
    witness: {
      preStateRoot: fieldStr(0n),
      postStateRoot: fieldStr(postStateRoot),
      caller: fieldStr(caller),
      to: fieldStr(to),
      amount: fieldStr(amount),
      minter: fieldStr(minter),
      balanceTo: fieldStr(balanceTo),
    }
  };
}

// Build a burn witness
export function buildBurnWitness({ tree, fromIdx, from, amount, balanceFrom }) {
  from = BigInt(from);
  amount = BigInt(amount);
  balanceFrom = BigInt(balanceFrom);

  const preStateRoot = tree.root;
  const proof = tree.getProof(fromIdx);

  // Post-state: reduced balance
  const newBalance = balanceFrom - amount;
  const postStateRoot = mimcHash(from, newBalance);

  return {
    circuit: 'burn',
    witness: {
      preStateRoot: fieldStr(preStateRoot),
      postStateRoot: fieldStr(postStateRoot),
      from: fieldStr(from),
      amount: fieldStr(amount),
      balanceFrom: fieldStr(balanceFrom),
      ...flattenProof(proof, 20),
    }
  };
}

// Build an approve witness
export function buildApproveWitness({ caller, owner, spender, amount }) {
  caller = BigInt(caller);
  owner = BigInt(owner);
  spender = BigInt(spender);
  amount = BigInt(amount);

  // Approve has simplified state roots (no Merkle tree)
  const postStateRoot = mimcHash(spender, amount);

  return {
    circuit: 'approve',
    witness: {
      preStateRoot: fieldStr(0n),
      postStateRoot: fieldStr(postStateRoot),
      caller: fieldStr(caller),
      spender: fieldStr(spender),
      amount: fieldStr(amount),
      owner: fieldStr(owner),
    }
  };
}

// Build a transferFrom witness
export function buildTransferFromWitness({
  balanceTree, allowanceTree, from, to, caller, amount,
  balanceFrom, allowanceFrom, balanceFromIdx, allowanceFromIdx
}) {
  from = BigInt(from);
  to = BigInt(to);
  caller = BigInt(caller);
  amount = BigInt(amount);
  balanceFrom = BigInt(balanceFrom);
  allowanceFrom = BigInt(allowanceFrom);

  // Pre-state: balance root and allowance root combined
  const balanceProof = balanceTree.getProof(balanceFromIdx);
  const allowanceProof = allowanceTree.getProof(allowanceFromIdx);
  const preStateRoot = mimcHash(balanceTree.root, allowanceTree.root);

  // Post-state
  const newBalance = balanceFrom - amount;
  const newAllowance = allowanceFrom - amount;
  const allowanceKey = mimcHash(from, caller);
  const postBalanceLeaf = mimcHash(from, newBalance);
  const postAllowanceLeaf = mimcHash(allowanceKey, newAllowance);
  const postStateRoot = mimcHash(postBalanceLeaf, postAllowanceLeaf);

  const witness = {
    preStateRoot: fieldStr(preStateRoot),
    postStateRoot: fieldStr(postStateRoot),
    from: fieldStr(from),
    to: fieldStr(to),
    caller: fieldStr(caller),
    amount: fieldStr(amount),
    balanceFrom: fieldStr(balanceFrom),
    allowanceFrom: fieldStr(allowanceFrom),
  };

  // Flatten balance proof (10 levels)
  for (let i = 0; i < 10; i++) {
    witness[`balancePath${i}`] = fieldStr(balanceProof.pathElements[i]);
    witness[`balanceIndex${i}`] = fieldStr(BigInt(balanceProof.pathIndices[i]));
    witness[`allowancePath${i}`] = fieldStr(allowanceProof.pathElements[i]);
    witness[`allowanceIndex${i}`] = fieldStr(BigInt(allowanceProof.pathIndices[i]));
  }

  return { circuit: 'transferFrom', witness };
}

// Build a voteCast witness
// tree: MerkleTree with voter commitments (mimcHash(voterSecret, voterWeight) as leaves)
// voterIdx: index of voter's leaf in tree
// pollId: unique poll identifier (BigInt)
// voterSecret: voter's secret derived from wallet signature (BigInt)
// voteChoice: the choice index (BigInt, 0-255)
// voterWeight: voter's weight in the registry (BigInt)
export function buildVoteCastWitness({ tree, voterIdx, pollId, voterSecret, voteChoice, voterWeight, maxChoices }) {
  pollId = BigInt(pollId);
  voterSecret = BigInt(voterSecret);
  voteChoice = BigInt(voteChoice);
  voterWeight = BigInt(voterWeight);
  maxChoices = BigInt(maxChoices || 256);

  // Voter registry root from Merkle tree
  const voterRegistryRoot = tree.root;
  const proof = tree.getProof(voterIdx);

  // Nullifier: deterministic per voter per poll, unlinkable across polls
  const nullifier = mimcHash(voterSecret, pollId);

  // Vote commitment: binds choice to voter secret (blinded — can't brute-force)
  const voteCommitment = mimcHash(voterSecret, voteChoice);

  return {
    circuit: 'voteCast',
    witness: {
      pollId: fieldStr(pollId),
      voterRegistryRoot: fieldStr(voterRegistryRoot),
      nullifier: fieldStr(nullifier),
      voteCommitment: fieldStr(voteCommitment),
      maxChoices: fieldStr(maxChoices),
      voterSecret: fieldStr(voterSecret),
      voteChoice: fieldStr(voteChoice),
      voterWeight: fieldStr(voterWeight),
      ...flattenProof(proof, 20),
    }
  };
}

// Bin count for the v3 (homomorphic) per-voter circuit. Must stay in
// lockstep with prover.VoteCastHomomorphicChoices on the Go side.
export const HOMOMORPHIC_CHOICES = 8;

// Tree depth for the homomorphic voter registry (matches voteCast).
const HOMOMORPHIC_DEPTH = 20;

// buildVoteCastHomomorphicWitness — assembles a v3 (homomorphic-tally)
// per-voter circuit assignment. Returns:
//   {
//     circuit: 'voteCastHomomorphic_8',
//     witness: { ... flat decimal-string fields ready for the WASM prover ... },
//     nullifier:        BigInt (mimc(secret, pollId)),
//     ciphertextsHex:   [{ A: hex, B: hex }, ...]   // K entries; what to send to /vote
//   }
//
// Inputs:
//   tree         — MerkleTree of voter commitments (depth 20).
//   voterIdx     — voter's leaf index in `tree`.
//   pollId       — BigInt poll id.
//   voterSecret  — BigInt; coercion-resistant derivation lives in poll.js.
//   voterWeight  — BigInt; usually 1.
//   choice       — int in [0, maxChoices).
//   maxChoices   — int in [1, HOMOMORPHIC_CHOICES].
//   pkCreatorHex — 32-byte compressed BabyJubJub hex.
//   randomness   — optional [BigInt; K]; if omitted, derived deterministically
//                  from (voterSecret, pollId, j) via mimcHash so the same
//                  voter resubmitting produces identical ciphertexts (avoids
//                  accidental nullifier reuse with different ciphertexts,
//                  which would still be rejected by the server but is
//                  noisy in logs). Production callers SHOULD pass real
//                  randomness — see poll.js.
//
// The circuit's range bound (V[j] = 0 for j ≥ maxChoices) is enforced
// by `probe = V[j] · (maxChoices − (j+1))` decomposing to 4 bits, so
// callers must place the one-hot 1 at index `choice` in [0, maxChoices).
export function buildVoteCastHomomorphicWitness({
  tree, voterIdx,
  pollId, voterSecret, voterWeight,
  choice, maxChoices,
  pkCreatorHex,
  randomness,
}) {
  pollId = BigInt(pollId);
  voterSecret = BigInt(voterSecret);
  voterWeight = BigInt(voterWeight);

  if (!Number.isInteger(choice) || choice < 0 || choice >= maxChoices) {
    throw new Error(`buildVoteCastHomomorphicWitness: choice=${choice} not in [0, ${maxChoices})`);
  }
  if (!Number.isInteger(maxChoices) || maxChoices < 1 || maxChoices > HOMOMORPHIC_CHOICES) {
    throw new Error(`buildVoteCastHomomorphicWitness: maxChoices=${maxChoices} not in [1, ${HOMOMORPHIC_CHOICES}]`);
  }

  const pk = decodePointHex(pkCreatorHex);

  const voterRegistryRoot = tree.root;
  const proof = tree.getProof(voterIdx);

  const nullifier = mimcHash(voterSecret, pollId);

  // Build one-hot V and per-bin randomness R.
  const V = new Array(HOMOMORPHIC_CHOICES).fill(0n);
  V[choice] = 1n;

  const R = new Array(HOMOMORPHIC_CHOICES);
  for (let j = 0; j < HOMOMORPHIC_CHOICES; j++) {
    if (randomness && randomness[j] !== undefined) {
      R[j] = BigInt(randomness[j]);
    } else {
      // Deterministic but per-voter-per-poll-per-bin. mimc is a field
      // function so the result is in Fr; reduce mod ℓ for the curve.
      const r = mimcHash(mimcHash(voterSecret, pollId), BigInt(j));
      R[j] = ((r % SUBGROUP_ORDER) + SUBGROUP_ORDER) % SUBGROUP_ORDER;
    }
  }

  // Encrypt each bin under pkCreator.
  const ciphertexts = R.map((r, j) => pedersenEncrypt(V[j], r, pk));
  const ciphertextsHex = ciphertexts.map((ct) => ({
    A: encodePointHex(ct.A),
    B: encodePointHex(ct.B),
  }));

  // Flat witness for the WASM prover. Points are split into X / Y
  // decimal strings; the gnark witness layout consumes them in field
  // declaration order.
  const witness = {
    pollId: fieldStr(pollId),
    voterRegistryRoot: fieldStr(voterRegistryRoot),
    nullifier: fieldStr(nullifier),
    maxChoices: fieldStr(BigInt(maxChoices)),

    'pkCreator.X': fieldStr(pk.x),
    'pkCreator.Y': fieldStr(pk.y),

    voterSecret: fieldStr(voterSecret),
    voterWeight: fieldStr(voterWeight),
  };
  for (let j = 0; j < HOMOMORPHIC_CHOICES; j++) {
    witness[`V${j}`] = fieldStr(V[j]);
    witness[`R${j}`] = fieldStr(R[j]);
    witness[`CtA${j}.X`] = fieldStr(ciphertexts[j].A.x);
    witness[`CtA${j}.Y`] = fieldStr(ciphertexts[j].A.y);
    witness[`CtB${j}.X`] = fieldStr(ciphertexts[j].B.x);
    witness[`CtB${j}.Y`] = fieldStr(ciphertexts[j].B.y);
  }
  for (let i = 0; i < HOMOMORPHIC_DEPTH; i++) {
    witness[`pathElement${i}`] = fieldStr(proof.pathElements[i]);
    witness[`pathIndex${i}`] = fieldStr(BigInt(proof.pathIndices[i]));
  }

  return {
    circuit: 'voteCastHomomorphic_8',
    witness,
    nullifier,
    ciphertextsHex,
  };
}

// buildTallyDecryptWitness — creator's decrypt-proof witness for v3
// poll close. Returns { circuit, witness, tallies } where `tallies`
// is the recovered per-bin plaintext (also bound into the proof's
// public inputs).
//
// Inputs:
//   skCreator        — BigInt (the creator's private key; never sent to server).
//   aggregatesHex    — [{A: hex, B: hex}; K] from GET /api/polls/{id}/votes
//                      (or from local re-aggregation of the public ciphertexts).
//   tallies          — optional [BigInt|int; K]. If omitted, derived by
//                      decrypting each bin under skCreator with maxTally
//                      defaulting to 65535.
export function buildTallyDecryptWitness({
  skCreator,
  aggregatesHex,
  tallies,
  maxTally = 65535,
}) {
  skCreator = BigInt(skCreator);
  if (aggregatesHex.length !== HOMOMORPHIC_CHOICES) {
    throw new Error(`expected ${HOMOMORPHIC_CHOICES} aggregates, got ${aggregatesHex.length}`);
  }

  const pk = scalarMulBase(skCreator);

  const aggregates = aggregatesHex.map((c) => ({
    A: decodePointHex(c.A),
    B: decodePointHex(c.B),
  }));

  let recovered;
  if (tallies && tallies.length === HOMOMORPHIC_CHOICES) {
    recovered = tallies.map((t) => BigInt(t));
  } else {
    recovered = aggregates.map((ct) => decryptToBigInt(ct, skCreator, maxTally));
  }

  // Range check mirroring the circuit's 16-bit bound.
  for (let j = 0; j < recovered.length; j++) {
    if (recovered[j] < 0n || recovered[j] > 0xffffn) {
      throw new Error(`tally[${j}] = ${recovered[j]} out of [0, 65535]`);
    }
  }

  const witness = {
    'pkCreator.X': fieldStr(pk.x),
    'pkCreator.Y': fieldStr(pk.y),
    skCreator: fieldStr(skCreator),
  };
  for (let j = 0; j < HOMOMORPHIC_CHOICES; j++) {
    witness[`A${j}.X`] = fieldStr(aggregates[j].A.x);
    witness[`A${j}.Y`] = fieldStr(aggregates[j].A.y);
    witness[`B${j}.X`] = fieldStr(aggregates[j].B.x);
    witness[`B${j}.Y`] = fieldStr(aggregates[j].B.y);
    witness[`Tallies${j}`] = fieldStr(recovered[j]);
  }

  return {
    circuit: 'tallyDecrypt_8',
    witness,
    tallies: recovered.map((t) => Number(t)),
  };
}

// decryptToBigInt — small-range DL search returning BigInt. Throws if
// the aggregate doesn't decrypt within [0, maxTally].
function decryptToBigInt(ct, sk, maxTally) {
  const skA = scalarMul(sk, ct.A);
  const M = pointAdd(ct.B, pointNeg(skA));
  if (M.x === PEDERSEN_ZERO.x && M.y === PEDERSEN_ZERO.y) return 0n;
  let probe = PEDERSEN_ZERO;
  for (let t = 1; t <= maxTally; t++) {
    probe = pointAdd(probe, PEDERSEN_G);
    if (probe.x === M.x && probe.y === M.y) return BigInt(t);
  }
  throw new Error(`decryptToBigInt: tally exceeds maxTally=${maxTally}`);
}

// Build a vesting claim witness
export function buildVestClaimWitness({
  scheduleTree, ownerTree, tokenID, caller, claimAmount,
  vestedAmount, claimed, owner, scheduleIdx, ownerIdx
}) {
  tokenID = BigInt(tokenID);
  caller = BigInt(caller);
  claimAmount = BigInt(claimAmount);
  vestedAmount = BigInt(vestedAmount);
  claimed = BigInt(claimed);
  owner = BigInt(owner);

  const scheduleProof = scheduleTree.getProof(scheduleIdx);
  const ownerProof = ownerTree.getProof(ownerIdx);
  const preStateRoot = mimcHash(scheduleTree.root, ownerTree.root);

  // Post-state: updated claimed amount
  const newClaimed = claimed + claimAmount;
  const postStateRoot = mimcHash(tokenID, newClaimed);

  const witness = {
    preStateRoot: fieldStr(preStateRoot),
    postStateRoot: fieldStr(postStateRoot),
    tokenID: fieldStr(tokenID),
    caller: fieldStr(caller),
    claimAmount: fieldStr(claimAmount),
    vestedAmount: fieldStr(vestedAmount),
    claimed: fieldStr(claimed),
    owner: fieldStr(owner),
  };

  for (let i = 0; i < 10; i++) {
    witness[`schedulePath${i}`] = fieldStr(scheduleProof.pathElements[i]);
    witness[`scheduleIndex${i}`] = fieldStr(BigInt(scheduleProof.pathIndices[i]));
    witness[`ownerPath${i}`] = fieldStr(ownerProof.pathElements[i]);
    witness[`ownerIndex${i}`] = fieldStr(BigInt(ownerProof.pathIndices[i]));
  }

  return { circuit: 'vestClaim', witness };
}
