# Phase B Roadmap — Eliminate the Reveal Phase

Tracking document for the remaining work to deliver `VoteSchemaVersion = 3`: end-to-end private voting where no individual choice is ever published, and the tally is a ZK-verified decryption of an aggregate ciphertext.

**Status:** B1–B5 done. v3 protocol is functionally complete, all server-side circuits prove + verify, and the disk-leakage acceptance test passes. **One known limitation:** browser-side WASM proving is blocked on an upstream gnark serialization bug (see `docs/wasm-prove-bug.md`); v3 polls are usable via API but not via the browser UI today.

Phase A (issues 1–4) shipped separately — see git history for `cmd/prover-wasm`, `internal/server/tally_proof.go`, `prover/tally_gen*.go`, `public/poll.js`.

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

### B2. Pedersen / ElGamal primitives — DONE

**Delivered:**
- `prover/pedersen.go` — `PedersenG`, `PedersenH` (cached), `Encrypt`, `Aggregate`, `Decrypt` (small-range DL up to maxTally), `EncodePoint`/`DecodePoint` (32-byte gnark-crypto compressed), `Ciphertext`, `ErrTallyExceedsRange`.
- `public/pedersen.js` — pure-bigint mirror: BN254 G1 affine arithmetic, compressed encoding (top-bit lex flags), `encrypt`/`aggregate`/`decrypt`, `setPedersenH`/`getPedersenH`.
- `prover/pedersen_test.go` — Go correctness + `TestEmitParityVectors` (gated on `BITWRAP_EMIT_VECTORS=1`) emits `public/pedersen_vectors.json`.
- `public/pedersen_parity_test.mjs` — asserts byte-equality on Fp/Fr, G, H, pk=G^sk, four encrypt cases, aggregate, decrypt.
- `prover/pedersen_jsparity_test.go` — invokes `node` to run the JS parity test as part of `go test ./...`.

**Decisions made:**
- `hash_to_curve`: gnark-crypto's RFC9380 SVDW map (`bn254.HashToG1(nil, "bitwrap-h-generator-v1")`). Pinned `H = 9feca7cde079df72328597882fe0d3c1f5674dc9273e92ed0a072667dfedf6cb`.
- Point encoding: 32-byte compressed (gnark-crypto layout) with top-2-bit flags (`0b10` smallest-y, `0b11` largest-y, `0b01` infinity). Lex comparison uses `y > (p-1)/2`.
- JS does not recompute hash-to-curve; H is loaded from `pedersen_vectors.json` and parity-asserted. Acceptable because H is a public deterministic constant — both sides must agree on bytes, not algorithm. Revisit if a JS-only deployment needs to derive H independently.
- Custody (open Q2): **client-only**. `sk_creator` never leaves the browser. Documented in B5 work; no server surface for sk in B2.
- **Curve choice corrected vs. spec.** Spec said BN254 G1, but doing G1 ops *inside* a BN254 Groth16 circuit requires non-native field emulation (~50× cost overhead). Switched to **BabyJubJub** — twisted Edwards over BN254's scalar field Fr, the standard "embedded curve" used by MACI / Semaphore / Tornado / Aztec / ZCash Sapling for exactly this reason. Constraint cost lands at ~70k for K=8 (matches the spec's 50–80k target); BN254-G1 + emulation would have been 200–500k. The protocol is otherwise unchanged. Update `docs/homomorphic-tally-spec.md` accordingly when next touched.

### B3. `VoteCastHomomorphicCircuit_8` — DONE

**Delivered:**
- `prover/vote_homomorphic_gen.go` — gnark Groth16 circuit for K=8.
- `prover/vote_homomorphic_test.go` — 1 happy-path acceptance + 5 refusal tests (two-hot, non-boolean, out-of-range bin, forged ElGamal, bad nullifier), each verified on both Groth16 and PLONK backends. Plus a constraint-count reporting test.
- Registered in `prover/circuits.go` as a lazy circuit (`voteCastHomomorphic_8`) — only v3 polls compile it.

**Constraints:** 72,253 for K=8 — within the spec's 50–80k target. Includes K=8 ElGamal binding pairs (A and B per bin) on BabyJubJub, a 4-bit MaxChoices range bound preventing votes at unused bins, depth-20 Merkle path with MiMC, and the standard nullifier mimc binding.

**Public inputs:** `PollID`, `VoterRegistryRoot`, `Nullifier`, `MaxChoices`, `PkCreator` (BabyJubJub point), `CtA[8]`, `CtB[8]` (BabyJubJub points).

**Private witness:** `VoterSecret`, `VoterWeight`, `V[8]` (one-hot), `R[8]` (randomness), `PathElements[20]`, `PathIndices[20]`.

**Open follow-ups for B5 wiring:**
- Witness builder in `public/witness-builder.js` for the JS / WASM proving path.
- Server endpoint to accept v3 ciphertexts + proof.
- The `_64` and `_256` size variants if larger polls land — current circuit is K=8.

### B4. `TallyDecryptCircuit_8` — DONE

**Delivered:**
- `prover/tally_decrypt_gen.go` — gnark Groth16 circuit (K=8) over BabyJubJub.
- `prover/tally_decrypt_test.go` — 1 happy-path acceptance + 3 refusal tests (wrong tally, wrong sk, oversized tally), each on Groth16 and PLONK. Plus a constraint-count reporting test.
- Registered as a lazy circuit (`tallyDecrypt_8`) in `prover/circuits.go`.

**Constraints:** 40,958 — higher than the spec's 10–20k estimate (the spec underweighted full-width sk·A scalar mults). Still ~half of B3 and well under 1s expected proving time.

**Public:** `PkCreator`, `A[8]`, `B[8]`, `Tallies[8]`. **Private:** `SkCreator`.

**Constraints encoded:**
1. `PkCreator = G · SkCreator`
2. For each j: `B[j] = G · Tallies[j] + A[j] · SkCreator`
3. `Tallies[j]` fits in 16 bits (range bound for on-chain verifier sanity)

**Optimization opportunity (deferred):** `gnark`'s `ScalarMul` runs full Fr-width (~250 bits) regardless of the scalar's actual size. Inlining a 16-bit binary-recomposition mult for `G · Tallies[j]` would save ~2–3k constraints per bin. `DoubleBaseScalarMul` was tried and is *slower* on this curve since it also assumes full-width scalars.

### B5. v3 schema + server + client + UI — DONE (with one limitation)

Landed across 11 sub-slices in commits `e04a8db` … `19a6453`:

| | | |
|---|---|---|
| B5.1 | v3 storage + tally artifact | `e04a8db` |
| B5.2 | poll-creation v3 branch (server) | `e64ce12` |
| B5.3 | vote-submission v3 branch (server) | `7c553ef` |
| B5.4 | `POST /api/polls/{id}/aggregate` + GET tally | `e793187` |
| B5.5 | reveal/results gating for v3 | `b56ab1d` |
| B5.6 | JS witness builders + Go↔JS parity | `67867fc` |
| B5.7a | v3 circuits in WASM `circuitByName` | `a4e55b9` |
| B5.7b | `castVoteV3` in `poll.js` | `27546f5` |
| B5.7d | `GET /api/polls/{id}/votes` audit endpoint | `3e133b2` |
| B5.8a | sk-creator localStorage + backup module | `f7b7f10` |
| B5.8b | `createPoll` v3 branch | `9599771` |
| B5.8c | `closePollV3` (client-side aggregate + decrypt) | `07f17c5` |
| B5.9 | UI surface (toggle, banners, results) | `25e53dd` |
| B5.10a/b | Playwright spec + project | `a18f9c5` |
| B5.10c | "no choice on disk" acceptance test | `bd58b48` |
| B5.10d | CI wiring | (auto, no commit) |
| B5.11 | client-side proving-key serving | `b3c3410` |

**The one limitation:** B5.11 wired all the infrastructure for
browser-side proving (proving-key endpoint, witness factory, embed
fix, content-types, `loadKeys` calls in `poll.js`) but the WASM
prover fails at constraint #2459 when given keys serialized by
native Go and reloaded into a wasm32 binary. Localized in
commit `19a6453` and written up at `docs/wasm-prove-bug.md`.

Concrete impact today:

- v3 protocol works end-to-end via direct API + Go-side proving
  (verified by `TestCastVoteV3HappyPath`,
  `TestAggregateV3HappyPath`, `TestV3PollDirHasNoChoiceLeakage`).
- v3 polls created from the UI render correctly, the v2/v3
  banner switches, sk_creator backs up — all the create-side
  pieces work.
- Voting and closing a v3 poll from a browser is blocked on the
  WASM prove path. Anyone with server-side context can drive the
  full lifecycle; voters with only a browser cannot.

The v2 (coercion-resistant + reveal-based) flow is unaffected
and remains the default in the create-poll UI.

## Remaining work

The privacy contract is fully delivered. The work that's left is
all about closing out the browser-side UX gap:

1. **Resolve the WASM proving bug.** See `docs/wasm-prove-bug.md`
   for the full localization. Four remediation paths are listed
   there with trade-offs; the cleanest is filing an upstream gnark
   issue with the reproduction artifacts already committed in
   `prover/cs_roundtrip_test.go`, `public/v3_wasm_prove_diag.mjs`,
   and `public/v3_wasm_compile_prove_diag.mjs`. A 1-line fix in
   gnark's CBOR encoding (force int64 width) is the likely
   resolution. Until then, v3 polls are server-operator-only.

2. **Re-enable the full Playwright lifecycle.** The skipped test
   in `e2e/v3.spec.js` (`create → register → vote → close`)
   becomes the natural acceptance gate for the WASM fix. The
   harness (sk_creator generation, wallet-fixture signing,
   download capture) is already in place — only the WASM prove
   step blocks it.

3. **Threshold decryption (v3.1).** Single-creator-key risk is the
   biggest open privacy gap in v3.0: a compromised creator key
   retroactively decrypts every ballot. The protocol surface
   (`/aggregate`, `tallyDecrypt_8`) was designed so threshold can
   drop in later without protocol changes — see open question 3
   below. Out of scope for v3.0; tracked as Phase C.

## Original open questions, now resolved

The questions captured at the start of B5 — locked in during
planning and reflected in the current implementation.

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

## B5.11 — client-side proving keys (DONE except follow-up bug)

Wires the in-browser WASM prover end-to-end against persisted
proving keys. Status:

**Delivered:**
- v3 circuits added to `standardCircuits()` so the keystore
  compiles + persists their cs/pk/vk at server startup.
- `KeyStore.ExportConstraintSystem` and `ExportProvingKey`
  alongside the existing `ExportVerifyingKey`.
- New `GET /api/keys/{circuit}.{cs|pk|vk}` endpoint serving raw
  bytes from the keystore. Five tests cover the dispatch shape.
- `prover/witness_v3_assignment.go` adds witness-factory cases
  for `voteCastHomomorphic_8` and `tallyDecrypt_8` so the WASM
  bundle's `bitwrapProver.prove(name, witness)` can build the
  matching gnark assignment from a JS-style witness map.
- `cmd/prover-wasm/main.go` already dispatches the v3 circuit
  names through `circuitByName` (B5.7a).
- `public/embed.go` extended to embed `*.wasm` so the bundle is
  actually served — previously the embed pattern only included
  HTML/JS/CSS/SVG and `prover.wasm` 404'd.
- `Content-Type: application/wasm` on .wasm responses so
  `instantiateStreaming` works.
- `castVoteV3` and `closePollV3` in `public/poll.js` call
  `loadKeys('voteCastHomomorphic_8', '/api/keys')` (and the
  matching `tallyDecrypt_8`) before `workerProve`. Module-level
  `_v3CircuitsLoaded` set caches across the SPA so the multi-MB
  PK fetch only happens once per session.

**Outstanding:** browser-side prove of `voteCastHomomorphic_8`
fails with `constraint #2459 is not satisfied` mid-ElGamal-binding.

Localization (commit set after the initial slice):
- The same witness passes `TestProveFromDumpedWitness` in native Go
  (witness dumped from a real Playwright run, replayed against a
  freshly-compiled circuit) — so the JS witness builder is correct.
- A native `TestCSRoundTripNativeProve` that serializes cs+pk+vk to
  bytes and reads them back round-trips cleanly — so the byte
  format is not the issue.
- WASM `compileCircuit` + `prove` against the same JS witness
  succeeds — confirms the WASM gnark prove path works on a freshly
  compiled cs.
- WASM `loadKeys` (with bytes from native Go's `WriteTo`) + `prove`
  against the same JS witness FAILS at constraint #2459. The
  asserted-equal value on the right matches the witness's CtA[0].X
  exactly, and the left value is what the in-circuit
  scalarMulFakeGLV hint produces from G·R[0] — different output
  for the same input.
- Hint IDs match between native and WASM (verified with
  `TestHintIDsNative` + WASM diagnostic dump): halfGCD=726531982,
  scalarMulHint=1399717548, decomposeScalar=1582912298. So the
  hint-resolution path is correct.
- Native + `-tags=purego` (which selects the same fr arithmetic
  backend the wasm bundle uses) round-trips correctly. So the
  pure-Go field arithmetic isn't the issue.

The bug is in the gnark cs+pk round-trip across architectures
(64-bit native ↔ 32-bit wasm32) — likely platform-dependent
encoding inside the constraint system bytes that the
`internal/backend/ioutils` layer or the CBOR body produces. A
fresh in-WASM compile yields a working cs+pk pair, but the bytes
written by native and read by WASM diverge somewhere subtle.

The acceptance criterion (no per-voter choice on disk) is enforced
by `internal/server/v3_disk_test.go` which runs the full lifecycle
in Go via the same circuits and proves the privacy property.
Browser-side proving is a UX feature, not a privacy gate — its
absence doesn't change the security posture.

The Playwright `v3.spec.js` keeps the create/UI flow tests green
and skips the full vote/close lifecycle pending this fix.

## Not in scope for Phase B

- Solidity verifier generation for the homomorphic circuits. Doable — the existing `/api/vk/{circuit}/solidity` pipeline already supports any compiled circuit — but confirm after B5 lands.
- On-chain settlement of v3 tallies. Phase B keeps everything server-side; settlement hooks land in a later slice once the off-chain flow is proven.
- Threshold-decrypt (v3.1). See open question 3.

## How to resume this work

Phase B is delivered. If you're picking up where it left off:

1. **Browser-prover bug.** Read `docs/wasm-prove-bug.md`. Run the
   five labeled diagnostics to confirm the bug still reproduces
   on your machine + gnark version. Pick a remediation path
   (likely #4: file the upstream issue with the reproduction
   artifacts).
2. **After the bug is fixed**, un-skip the lifecycle test in
   `e2e/v3.spec.js` (look for the `test.skip` block) — that test
   exercises the full create → vote → close UI flow.
3. **Phase C / v3.1 (threshold decryption)** is the next protocol
   evolution. The hooks are in place — `/aggregate` doesn't care
   how many parties produced the decrypt proof, and the circuit
   doesn't care either. The work is the t-of-n key-sharing
   ceremony + a multi-party `sk_creator` substitute.

For new circuit families more broadly: `prover/vote_homomorphic_gen.go`
+ `prover/tally_decrypt_gen.go` are the reference for how a v3-shaped
circuit gets wired in (BabyJubJub points as public inputs, in-circuit
ScalarMul, MiMC nullifier, Merkle membership).
`internal/server/keys_endpoint_test.go` shows how to plumb keystore
serving for in-browser proving once the WASM bug is resolved.
