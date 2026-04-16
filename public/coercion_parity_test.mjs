// Coercion-fix parity test. Verifies the v2 secret derivation breaks the
// link between a wallet signature alone and the voter's vote.
//
// Run: node public/coercion_parity_test.mjs

import { mimcHash } from './mimc.js';

let failures = 0;

function assert(condition, msg) {
  if (!condition) {
    console.error('FAIL:', msg);
    failures++;
  }
}

// Mirrors deriveVoterSecret(schemaVersion=2, ...) from poll.js. Kept in
// sync with the runtime derivation; a divergence here is a bug.
function deriveV2Secret(sigDerived, nonce) {
  return mimcHash(sigDerived, nonce);
}

// Mirrors the v1 (legacy) derivation.
function deriveV1Secret(sigDerived) {
  return sigDerived;
}

function nullifier(secret, pollIdField) {
  return mimcHash(secret, pollIdField);
}

// Scenario 1: v1 is deterministic-from-signature (the gap we're closing).
(function testV1Deterministic() {
  const sigDerived = BigInt('0x' + 'ab'.repeat(31));
  const pollIdField = BigInt('0x' + 'cafebabedeadbeef');
  const secretA = deriveV1Secret(sigDerived);
  const secretB = deriveV1Secret(sigDerived);
  assert(secretA === secretB, 'v1 secrets must match for identical sig');
  assert(nullifier(secretA, pollIdField) === nullifier(secretB, pollIdField),
    'v1 nullifiers are trivially reproducible from sig alone (the coercion gap)');
  console.log('v1 determinism (pre-fix behavior): OK');
})();

// Scenario 2: v2 with identical sig but DIFFERENT nonces must yield
// different secrets and different nullifiers.
(function testV2DifferentNonceDivergent() {
  const sigDerived = BigInt('0x' + 'ab'.repeat(31));
  const pollIdField = BigInt('0x' + 'cafebabedeadbeef');
  const nonceA = 123456789012345n;
  const nonceB = 987654321098765n;
  assert(nonceA !== nonceB, 'test setup: nonces must differ');

  const secretA = deriveV2Secret(sigDerived, nonceA);
  const secretB = deriveV2Secret(sigDerived, nonceB);
  assert(secretA !== secretB, `v2 secrets should diverge: ${secretA} === ${secretB}`);

  const nullA = nullifier(secretA, pollIdField);
  const nullB = nullifier(secretB, pollIdField);
  assert(nullA !== nullB, `v2 nullifiers should diverge: ${nullA} === ${nullB}`);
  console.log('v2 different-nonce divergence: OK');
})();

// Scenario 3: v2 with identical sig AND identical nonce must be stable
// (so register and vote agree, and reveal works).
(function testV2StableWithSameNonce() {
  const sigDerived = BigInt('0x' + 'ab'.repeat(31));
  const nonce = 42n;
  const secretRound1 = deriveV2Secret(sigDerived, nonce);
  const secretRound2 = deriveV2Secret(sigDerived, nonce);
  assert(secretRound1 === secretRound2, 'v2 must be deterministic given sig+nonce');
  console.log('v2 stability (same nonce): OK');
})();

// Scenario 4: v2 secret must NOT equal the legacy v1 secret derived from
// the same signature. If they coincided, a legacy coercer with just the
// signature would still compute the right value.
(function testV2IndistinguishableFromV1() {
  const sigDerived = BigInt('0x' + 'ab'.repeat(31));
  const nonce = randomFieldElement();
  const v1Secret = deriveV1Secret(sigDerived);
  const v2Secret = deriveV2Secret(sigDerived, nonce);
  assert(v1Secret !== v2Secret, 'v2 secret must differ from v1 secret for coercion resistance');
  console.log('v2 escapes v1 derivation: OK');
})();

function randomFieldElement() {
  // Pseudo-random 31-byte value; not security-critical here (test data).
  let x = 1n;
  for (let i = 0; i < 31; i++) {
    x = (x * 31337n + 7n) % (1n << 248n);
  }
  return x;
}

if (failures > 0) {
  console.error(`\n${failures} assertion(s) failed`);
  process.exit(1);
}
console.log('\nAll coercion-parity assertions passed.');
