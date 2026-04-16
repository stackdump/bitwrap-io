# Homomorphic Tally Protocol (v3 schema)

Status: design (not yet implemented). Supersedes the Pedersen-commitment sketch in the Phase B section of `~/.claude/plans/purring-tickling-shore.md`.

## Goal

Eliminate the reveal phase. Voters commit to a choice, ZK-prove the commit is well-formed, and the tally is derived **without any per-voter decryption**. The creator (or a threshold committee) decrypts **only the aggregate ciphertext** — which is small enough to brute-force — and publishes the tally with a ZK proof of correct decryption.

This closes the post-close deanonymization gap: even with every voter's wallet signature and the poll creator's secret key, an observer cannot recover an individual voter's choice from on-disk data alone.

## Design correction vs. the original plan

The plan sketched "Pedersen commitments + creator publishes `R_j = sum_i r_{i,j}` with a proof that `T_j = G^{tally_j} * H^{R_j}`."

**Why that design leaks:** to publish `R_j` honestly, the creator must know every `r_{i,j}`. Given `r_{i,j}` and the voter's commitment `C_{i,j} = G^{v_{i,j}} * H^{r_{i,j}}`, decrypting the binary vote is trivial — compute `C_{i,j} * H^{-r_{i,j}}` and check whether the result is the identity (vote=0) or `G` (vote=1). The creator can reconstruct every voter's choice.

**Correct design:** Helios-style additively homomorphic ElGamal over BN254's `G1`. Voters never reveal `r_{i,j}` — they instead submit **ciphertexts** that the creator can aggregate homomorphically. The creator decrypts only the aggregate — where the sum of 1s lives in a range small enough (0..N voters) to recover by baby-step-giant-step or linear scan.

## Primitives

- **Curve:** BN254 `G1` (native for gnark Groth16, same as existing circuits).
- **Generator G:** curve's canonical base point.
- **Generator H:** independent generator with unknown discrete log wrt G. Derived via "hash-to-curve" of the fixed string `bitwrap-h-generator-v1`. Verifiable deterministic construction; no trusted setup.
- **Creator keypair:** `sk_creator ∈ Z_p`, `pk_creator = G^{sk_creator}`. Published at poll creation, signed under the creator's Ethereum address.

## Vote encoding

Each voter picks a choice `c ∈ [0, K)`. Encoded as a one-hot vector `v ∈ {0, 1}^K` with exactly one `1` at position `c`.

For each bin `j`:
- Sample fresh randomness `r_{i,j} ∈ Z_p`.
- ElGamal ciphertext under `pk_creator`: `ct_{i,j} = (A_{i,j}, B_{i,j})` where
  - `A_{i,j} = G^{r_{i,j}}`
  - `B_{i,j} = G^{v_{i,j}} · pk_creator^{r_{i,j}}`

Voter submits `{ct_{i,0}, ..., ct_{i,K-1}}` + a single Groth16 proof attesting to:

1. Each `v_{i,j} ∈ {0, 1}` (binary).
2. `Σ_j v_{i,j} = 1` (exactly one active).
3. Each ciphertext is well-formed — same `r_{i,j}` used in both `A` and `B` (provable by standard ElGamal Schnorr-style binding, inlined in the circuit).
4. Voter is in the Merkle registry (same as today's `VoteCastCircuit`).
5. Nullifier binds to `pollId` (same as today).

## Aggregation

Anyone can aggregate ciphertexts bin-wise, using ElGamal's additive homomorphism:

```
A_j = Π_i A_{i,j} = G^{R_j}              where R_j = Σ_i r_{i,j}
B_j = Π_i B_{i,j} = G^{tally_j} · pk_creator^{R_j}
```

Where `tally_j` is the raw count of voters who picked bin `j`.

## Tally decryption

Only the creator can decrypt (they hold `sk_creator`):

```
M_j = B_j / A_j^{sk_creator}
    = G^{tally_j} · pk_creator^{R_j} / (G^{R_j})^{sk_creator}
    = G^{tally_j}
```

Then extract `tally_j` from `M_j` by trying `tally_j = 0, 1, ..., N` (small-range DL). N = number of voters; this is a linear scan, trivially feasible up to the poll size we care about (≤ 256 in v1).

**Crucially**, the creator never decrypts an individual ciphertext — they only decrypt the aggregate. No voter's choice is revealed to the creator.

## Creator's tally proof

When publishing `{tally_0, ..., tally_{K-1}}`, the creator attaches a ZK proof for each bin `j`:

Given public `(A_j, B_j, tally_j, pk_creator)`, prove there exists `sk_creator` such that:
- `pk_creator = G^{sk_creator}`
- `B_j = G^{tally_j} · A_j^{sk_creator}`

A Groth16 circuit with the creator's `sk_creator` as the private witness. Each bin's proof is independent; batched into a single `TallyDecryptCircuit_K` over K bins.

## Coercion-resistance boundary

v3 closes one of the two post-close linkability attacks:
- **Closed:** cleartext choices are no longer persisted in reveal events. Even with full server disk access, no observer reconstructs per-voter choices.
- **Open:** if the **creator's** `sk_creator` is compromised, all votes can be decrypted in retrospect (creator's key is a global trapdoor). Threshold-decryption across multiple coordinators is the real fix — flagged as v3.1 work.

## Data structures

### Per-vote submission (v3)

```json
{
  "nullifier": "0x...",
  "ciphertexts": [
    { "A": "0x...", "B": "0x..." },
    ...
    (K entries, one per choice bin)
  ],
  "proof":      "base64",
  "publicInputs": ["pollId", "registryRoot", "nullifier", "pkCreator", "maxChoices"]
}
```

### Tally artifact (v3)

```json
{
  "pollId": "...",
  "aggregate": [
    { "A": "0x...", "B": "0x..." },
    ...
    (K entries)
  ],
  "tallies": [t0, t1, ..., t_{K-1}],
  "decryptProof": "base64",
  "circuitName": "tallyDecrypt_K"
}
```

No `reveals.json` exists for v3 polls.

## Parity test vectors

At B2 delivery, each pair `(Go implementation, JS implementation)` must produce identical byte sequences for:

1. `H = hash_to_curve("bitwrap-h-generator-v1")` — deterministic single point.
2. `ct = Encrypt(v, r, pk)` — for a fixed set of `(v, r, pk)` triples.
3. `ct_agg = Σ cts` — aggregation of a fixed ciphertext list.
4. `M = Decrypt(ct_agg, sk)` — decryption under a fixed sk.

Failure of any parity test is a hard block on shipping v3. Both sides must round-trip against the same proof.

## Circuit sizes and proving costs

Rough constraint estimates per circuit:

- `VoteCastHomomorphic_K=8`: ~50–80k constraints (K ElGamal binds + K range checks + K-row sum + Merkle path + MiMC nullifier). Proving time ~2–5s in browser WASM.
- `TallyDecrypt_K=8`: ~10–20k constraints (K discrete-log opens). Fast.

These are estimates; measure and revise once implemented.

## Migration plan

- **v1 / v2 polls continue to work** as before. Reveal phase, tally-proof circuit, everything unchanged.
- **v3 polls are opt-in** at poll creation via a `schemaVersion: 3` field. Poll creation UI offers "Maximum privacy" as an option.
- No in-place upgrade — polls started under v1/v2 complete under their original scheme.

## Open questions (to resolve before implementing)

1. **Hash-to-curve for H:** pick a concrete standard. Default: `hash_to_curve(bn254_g1, domain="bitwrap-h-generator-v1")` using RFC9380. Requires an implementation both in Go (use `gnark-crypto/ecc/bn254`) and JS (implement against canonical test vectors).

2. **Creator keypair custody:** how does the creator avoid leaking `sk_creator` to the server? Options:
   - Creator signs the tally proof client-side; server receives the finished artifact. Requires the creator to be online when the poll closes.
   - Creator entrusts `sk_creator` to the server inside an encrypted envelope with a time-lock or multi-sig. Heavier — defer.

3. **Creator's pkCreator must be part of the voter's ZK proof public inputs**, otherwise a malicious server could swap the pk after votes are cast. Requires extending the voter-registry Merkle-root signing flow to also bind `pkCreator`.

4. **Encoding of curve points in the JSON API and proof public inputs:** compressed 32-byte `(x, y_odd)` is the natural choice. Document and parity-test.

## References

- Bernhard, Pereira, Warinschi — *How Not to Prove Yourself: Pitfalls of the Fiat-Shamir Heuristic and Applications to Helios* (useful caution for the decrypt proof).
- Helios 3.0 protocol doc.
- MACI v1 (minimum anti-collusion infrastructure) — threshold-decryption path; v3.1 target.
