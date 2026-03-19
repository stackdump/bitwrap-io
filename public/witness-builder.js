// Witness builder for bitwrap ZK circuits
// Builds complete witness objects ready to POST to /api/prove

import { mimcHash } from './mimc.js';
import { MerkleTree } from './merkle.js';

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
export function buildVoteCastWitness({ tree, voterIdx, pollId, voterSecret, voteChoice, voterWeight }) {
  pollId = BigInt(pollId);
  voterSecret = BigInt(voterSecret);
  voteChoice = BigInt(voteChoice);
  voterWeight = BigInt(voterWeight);

  // Voter registry root from Merkle tree
  const voterRegistryRoot = tree.root;
  const proof = tree.getProof(voterIdx);

  // Nullifier: deterministic per voter per poll, unlinkable across polls
  const nullifier = mimcHash(voterSecret, pollId);

  return {
    circuit: 'voteCast',
    witness: {
      pollId: fieldStr(pollId),
      voterRegistryRoot: fieldStr(voterRegistryRoot),
      nullifier: fieldStr(nullifier),
      voterSecret: fieldStr(voterSecret),
      voteChoice: fieldStr(voteChoice),
      voterWeight: fieldStr(voterWeight),
      ...flattenProof(proof, 20),
    }
  };
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
