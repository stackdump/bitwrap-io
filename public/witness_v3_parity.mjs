// Build a v3 (homomorphic) per-voter witness in JS and emit it as JSON
// for the Go side to consume. The Go-side parity test in
// prover/witness_v3_parity_test.go reads this output, builds the
// matching gnark assignment, runs Groth16 Prove + Verify, and asserts
// the JS witness layout actually satisfies the circuit.
//
// Run directly:
//   node public/witness_v3_parity.mjs > /tmp/v3-witness.json
//
// Or as part of `go test ./prover -run TestWitnessV3Parity` which
// shells out to `node` automatically.

import { mimcHash } from './mimc.js';
import { MerkleTree } from './merkle.js';
import { setPedersenH, getPedersenH, scalarMulBase, encodePointHex } from './pedersen.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  buildVoteCastHomomorphicWitness,
  buildTallyDecryptWitness,
} from './witness-builder.js';

const here = dirname(fileURLToPath(import.meta.url));
// Initialize the Pedersen H constant — required even though our
// witness builders don't use it directly, so that any future change
// surfaces here too.
const vectors = JSON.parse(readFileSync(join(here, 'pedersen_vectors.json'), 'utf8'));
setPedersenH(vectors.H);

// Fixed inputs so Go can recompute the expected witness bit-for-bit.
const POLL_ID = 0xfeedbeefn;
const VOTER_SECRET = 0x1234abcd5678efabn;
const VOTER_WEIGHT = 1n;
const CHOICE = 2;
const MAX_CHOICES = 5;
const SK_CREATOR = 0xc0ffeefacefeedn;

// Build a real depth-20 tree with the voter at index 0.
const leaf = mimcHash(VOTER_SECRET, VOTER_WEIGHT);
const tree = MerkleTree.fromLeaves([leaf], 20); // sibling slots are zero by construction

// Derive pkCreator deterministically.
const pk = scalarMulBase(SK_CREATOR);
const pkHex = encodePointHex(pk);

// Build per-voter witness.
const voteResult = buildVoteCastHomomorphicWitness({
  tree,
  voterIdx: 0,
  pollId: POLL_ID,
  voterSecret: VOTER_SECRET,
  voterWeight: VOTER_WEIGHT,
  choice: CHOICE,
  maxChoices: MAX_CHOICES,
  pkCreatorHex: pkHex,
});

// Build a tally-decrypt witness for an aggregate that's just this
// single voter's ciphertexts (so each bin's tally is V[j] itself).
const tallyResult = buildTallyDecryptWitness({
  skCreator: SK_CREATOR,
  aggregatesHex: voteResult.ciphertextsHex,
});

const out = {
  pollId: POLL_ID.toString(10),
  voterSecret: VOTER_SECRET.toString(10),
  voterWeight: VOTER_WEIGHT.toString(10),
  choice: CHOICE,
  maxChoices: MAX_CHOICES,
  skCreator: SK_CREATOR.toString(10),
  pkCreator: pkHex,

  voteCastHomomorphic: voteResult,
  tallyDecrypt: tallyResult,
};

process.stdout.write(JSON.stringify(
  out,
  (_k, v) => (typeof v === 'bigint' ? v.toString(10) : v),
  2,
));
