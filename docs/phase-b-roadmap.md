# Phase B Roadmap — Eliminate the Reveal Phase

Tracking document for the remaining work to deliver `VoteSchemaVersion = 3`: end-to-end private voting where no individual choice is ever published, and the tally is a ZK-verified decryption of an aggregate ciphertext.

**Status:** design approved, not yet implemented. Phase A (issues 1–4) shipped separately — see git history for `cmd/prover-wasm`, `internal/server/tally_proof.go`, `prover/tally_gen*.go`, `public/poll.js`.

## Why

Phase A closed four gaps (in-browser verify, registry signing, batch scaling, coercion-resistant voterSecret) but left the fundamental leak: at reveal time, the server still sees `(nullifier, choice, secret)` triples in cleartext. Given a voter's wallet signature, anyone with access to the public reveal events can link them to their vote.

Phase B removes the reveal step entirely. Votes are encrypted on submit, aggregated homomorphically, and decrypted only in aggregate. The design is Helios-style additively homomorphic ElGamal over BN254 `G1`.

## Protocol reference

Full technical spec: [`docs/homomorphic-tally-spec.md`](./homomorphic-tally-spec.md).

Key properties:
- Voter submits `K` ElGamal ciphertexts (one per choice bin) + a Groth16 proof of one-hot + range + binding + registry + nullifier.
- Anyone aggregates ciphertexts bin-wise — no secrets needed.
- Creator (or, in v3.1, a threshold committee) decrypts **only the aggregate** and publishes tallies with a ZK decrypt proof.
- Individual ciphertexts are never decrypted — so no per-voter choice ever appears in server state, disk, or log.

## Work breakdown

Estimated one-engineer effort: **2–4 weeks** end-to-end. Items are ordered by dependency; each builds on the previous.

### B1. Protocol specification — DONE

- **Deliverable:** [`docs/homomorphic-tally-spec.md`](./homomorphic-tally-spec.md)
- **Notes:** corrected a flaw in the original plan (publishing `R_j` leaks individual votes). Revised to ElGamal-with-aggregate-decrypt.

### B2. Pedersen / ElGamal primitives — NOT STARTED

**Goal:** reusable Go and JS libraries for the curve arithmetic and encryption, with byte-for-byte parity guaranteed.

- `prover/pedersen.go`
  - `H` generator derived via `hash_to_curve("bitwrap-h-generator-v1")`.
  - `Encrypt(v *big.Int, r *big.Int, pk Point) (A, B Point)`
  - `Aggregate(cts []Ciphertext) Ciphertext`
  - `Decrypt(ct Ciphertext, sk *big.Int, maxTally int) (int, error)` — small-range DL search.
- `public/pedersen.js` — bigint-based mirror of the above.
- Parity test: Go generates vectors (JSON), JS verifies byte-equality across `H`, encrypt, aggregate, decrypt.

**Open question before implementing:** pick an exact `hash_to_curve` standard. RFC9380 SSWU with domain `bitwrap-h-generator-v1` is the default; needs test vectors that both Go (`gnark-crypto/ecc/bn254`) and JS will match.

### B3. `VoteCastHomomorphicCircuit_K` — NOT STARTED

**Goal:** per-voter ZK proof of a well-formed encrypted ballot.

- `prover/pedersen_vote_gen.go`
- Public inputs: `pollId`, `registryRoot`, `nullifier`, `pkCreator`, `ciphertexts[K] = {A, B}`.
- Private witness: one-hot vector `v[K]`, randomness `r[K]`, voter's `secret`, Merkle path.
- Constraints:
  1. Each `v[j] ∈ {0, 1}` (boolean).
  2. `Σ v[j] = 1` (one-hot).
  3. `A[j] == G^{r[j]}` and `B[j] == G^{v[j]} · pkCreator^{r[j]}` (ElGamal binding).
  4. Merkle membership (same shape as today's `VoteCastCircuit`).
  5. `nullifier == mimcHash(secret, pollId)`.
- Circuit estimate: 50–80k constraints. Browser-WASM proving ~2–5s.

### B4. `TallyDecryptCircuit_K` — NOT STARTED

**Goal:** creator proves the decrypted tallies match the aggregate ciphertexts.

- `prover/pedersen_tally_gen.go`
- Public inputs: `pkCreator`, aggregates `(A_j, B_j)[K]`, claimed `tallies[K]`.
- Private witness: `skCreator`.
- Constraints:
  1. `pkCreator == G^{skCreator}`.
  2. For each `j`: `B_j == G^{tally_j} · A_j^{skCreator}`.
- Much smaller than B3 — ~10–20k constraints.

### B5. v3 schema + server + client + UI — NOT STARTED

**Goal:** stitch it all together behind a new schema version.

Server:
- Extend `Poll` with `PkCreator string` (hex point).
- `handleCastVote` v3 branch stores K ciphertexts instead of a single `voteCommitment`; never accepts a `VoterSecret`.
- New `POST /api/polls/{id}/aggregate` — creator-signed; server computes aggregate `(A_j, B_j)`, accepts creator's decrypt proof + tallies, persists as the tally artifact.
- Remove reveal endpoints for v3 polls. `store.RevealBundle` never written.

Client (`public/`):
- `pedersen.js` from B2.
- `poll.js` v3 branch: generate K ciphertexts, build circuit witness, WASM prove.
- Creator flow: generate `skCreator` at poll creation (client-side), sign + upload `pkCreator`; at close, download aggregate, decrypt locally, sign + upload tally + decrypt proof.
- UI removes the reveal step entirely for v3; "Close poll & publish tallies" is the creator's final action.

Tests:
- End-to-end Playwright: create v3 poll → register → vote (N voters) → creator closes → verify no file under `data/polls/{id}/` contains any voter's choice.
- Integration test: `/api/polls/{id}/reveal` returns 404 for v3 polls.
- Parity test: aggregate of N JS-generated ciphertexts decrypts identically in Go.

## Critical open questions

Answer these before B2 begins — the answers affect primitives and server surface.

1. **`hash_to_curve` standard for `H`.** Default recommendation: RFC9380 SSWU with domain `bitwrap-h-generator-v1`, using `gnark-crypto` on the Go side and a canonical implementation on the JS side. Alternative: try-and-increment (simpler, slightly less standard).

2. **Custody of `sk_creator`.** Two viable options:
   - **Client-only.** Creator generates the keypair in-browser, keeps it (localStorage or downloaded backup), never shares with the server. Creator must be online at close time. Simplest and cleanest; matches the coercion-fix philosophy of Phase A.
   - **Encrypted server envelope.** Creator uploads `sk_creator` encrypted to a server-held KMS key. Server can decrypt and close autonomously. Heavier; introduces a new trust surface. Defer.

3. **Threshold decryption for v3.1.** Single-creator custody means a compromised creator key retroactively decrypts every voter's choice. Proper fix is t-of-n threshold decryption across multiple coordinators. Explicit future-work item — don't block v3.0 on it, but design the tally endpoint and circuit so threshold can drop in later without protocol changes.

4. **UX for creators losing `sk_creator`.** If the creator loses the key, the poll can't be tallied. Mitigation: at creation, offer a downloaded-backup flow analogous to the voter-side coercion-fix backup. Single-creator trust model is already fragile — make the failure mode visible up front.

## What "done" looks like

Acceptance criteria (copied from the plan file for durability):

1. A closed v3 poll has **no `reveals.json` file** in its storage directory.
2. `/api/polls/{id}/tally-proof` for a v3 poll returns a proof whose public inputs include only `pollId`, `registryRoot`, per-bin aggregate ciphertexts, claimed tallies, and `pkCreator` — never a secret or choice.
3. Inspecting server logs and storage for an in-progress v3 poll, no voter's choice is reconstructible even with full disk access **plus** every voter's wallet signature.
4. JS ↔ Go parity test for ElGamal encrypt/aggregate/decrypt passes byte-for-byte.

## Not in scope for Phase B

- Solidity verifier generation for the homomorphic circuits. Doable — the existing `/api/vk/{circuit}/solidity` pipeline already supports any compiled circuit — but confirm after B5 lands.
- On-chain settlement of v3 tallies. Phase B keeps everything server-side; settlement hooks land in a later slice once the off-chain flow is proven.
- Threshold-decrypt (v3.1). See open question 3.

## How to resume this work

If you're picking this up cold:

1. Read `docs/homomorphic-tally-spec.md` — full protocol.
2. Answer open questions 1 and 2 above (pick `hash_to_curve` + `sk_creator` custody).
3. Start at B2. Everything downstream depends on the primitives being parity-verified.

The Phase A code in `prover/tally_*.go`, `prover/lazy_compile.go`, and `internal/server/tally_proof.go` is the reference for how a new circuit family gets wired in — sized variants, lazy compile, size dispatch, WASM `circuitByName`, and the `loadVerifyOnly` browser path. Same pattern applies to the B3 and B4 circuits.
