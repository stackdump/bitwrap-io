# Threshold Decryption Protocol (v3.1 / schema v4)

Status: design (not yet implemented). Extends [`docs/homomorphic-tally-spec.md`](./homomorphic-tally-spec.md) by replacing single-creator tally decryption with coordinator threshold decryption.

## Goal

Remove the v3.0 single-key trust point: compromise of one creator key must no longer retroactively decrypt all ballots.

## Decisions (resolved)

1. **Key generation ceremony:** **Pedersen DKG (t-of-n)**, not trusted-dealer Shamir.
2. **Coordinator selection model:** **creator-picked coordinator set** at poll creation for v3.1.
3. **Threshold defaults:** parameterized, default **n=5, t=4** (`t = ceil(2n/3)`).
4. **Circuits:** add **`PartialDecryptCircuit_K`** and **`CombinedDecryptCircuit_K_t`**.
5. **Liveness:** no creator-master-key fallback; use retry windows + coordinator replacement/re-share protocol.
6. **Coordinator identity/signing:** coordinator partial artifacts are signed with **EIP-191** (`personal_sign`) over canonical JSON payload hash.
7. **Backwards compatibility:** threshold polls use **`schemaVersion: 4`**.

---

## Compatibility and scope

- v1/v2/v3 poll behavior is unchanged.
- v4 keeps the same aggregate-close request shape (`POST /api/polls/{id}/aggregate`), but decryption artifacts differ.
- This spec covers off-chain threshold tally decryption and proof publication only.

## Threat model

- Adversary may compromise some coordinators and/or the server.
- Privacy must hold unless at least `t` decryption shares are compromised.
- Coordinator unavailability is expected; protocol must tolerate up to `n - t` offline coordinators.

## Protocol overview

### 1) Poll creation (v4)

Creator chooses:
- `choices = K`
- coordinator set `C = {c_1..c_n}`
- threshold `t` (default derived from `n`)

Creation artifact includes:
- `schemaVersion: 4`
- `threshold: { n, t }`
- `coordinators: [{ address, encPubKey, signingPubKey, endpoint }]`
- DKG transcript commitment root and resulting committee encryption public key `pk_committee`

Voters encrypt exactly as v3, except under `pk_committee` instead of `pk_creator`.

### 2) Vote casting and aggregation

Unchanged from v3 at API shape level:
- per-vote ciphertext vectors
- bin-wise aggregate ciphertexts `(A_j, B_j)`

### 3) Threshold decryption at close

For each coordinator `c_i` and bin `j`:
- compute partial decryption share `D_{i,j} = A_j^{s_i}`
- generate proof `π_i` (via `PartialDecryptCircuit_K`) that all `D_{i,*}` are consistent with coordinator public share `Y_i = G^{s_i}`
- sign partial artifact with EIP-191

Combiner accepts first `t` valid, unique partials and reconstructs:

`A_j^x = Π_{i in S} D_{i,j}^{λ_i(S)}`

Here `Π` is a group-element product (elliptic-curve point addition in exponent form), not integer multiplication.

where `S` is selected coordinator index set (`|S|=t`) and `λ_i(S)` are Lagrange coefficients at 0.

Then:

`M_j = B_j / A_j^x = G^{tally_j}`

Recover `tally_j` by bounded discrete log (`0..N_voters`) as in v3.

### 4) Final proof + publication

Publish tally artifact with:
- aggregate ciphertexts
- selected coordinator IDs
- accepted partial artifacts
- final decrypt proof `Π_final` from `CombinedDecryptCircuit_K_t`
- tallies

`CombinedDecryptCircuit_K_t` proves:
1. each included partial proof is valid for its coordinator share key
2. recombination from selected partials yields `A_j^x`
3. `B_j = G^{tally_j} * A_j^x` for all bins
4. tallies are range-bounded

## Circuit sketches

### `PartialDecryptCircuit_K`

**Public inputs**
- `A[0..K-1]`
- `D_i[0..K-1]`
- `Y_i`
- `pollId`
- `coordinatorIndex`

**Private witness**
- `s_i`

**Constraints (per bin `j`)**
1. `Y_i == G * s_i`
2. `D_i[j] == A[j] * s_i`

Plus domain-binding constraints to `pollId` and `coordinatorIndex`.

### `CombinedDecryptCircuit_K_t`

**Public inputs**
- `A[0..K-1]`, `B[0..K-1]`
- `tallies[0..K-1]`
- selected coordinator indices `S`
- selected public share keys `Y_i`
- selected partial points `D_i[j]`

**Private witness**
- Lagrange coefficients `λ_i(S)` (or recombination witness equivalent)
- internal recombined `Ax[j]`

**Constraints**
1. Verify each selected partial is linked to its coordinator share key (or include verified subproof commitments).
2. For each bin `j`: `Ax[j] == Π_i D_i[j]^{λ_i(S)}`
3. For each bin `j`: `B[j] == G * tallies[j] + Ax[j]`
4. `tallies[j]` bounded (same bound policy as v3, tightened to poll max voters)

## Coordinator signing format

Each coordinator signs the hash of canonical JSON:

```json
{
  "type": "bitwrap.threshold.partial.v1",
  "pollId": "...",
  "schemaVersion": 4,
  "coordinatorIndex": 2,
  "coordinatorAddress": "0x...",
  "aggregateHash": "0x...",
  "partialDecryptProofHash": "0x...",
  "timestamp": 1730000000
}
```

- Signature algorithm: EIP-191 (`personal_sign`) over `keccak256(canonical_payload_bytes)`.
- Verifier checks recovered address equals announced coordinator address.

## Liveness and recovery

v3.1 does **not** permit a single-party master-key fallback.

Recovery policy:
1. **Primary window:** request partials for `T_close` duration.
2. **Retry window:** rebroadcast + endpoint failover for `T_retry`.
3. **Coordinator replacement / re-share:** if still `< t`, creator proposes replacement set and a new committee key via a signed update artifact; update must be co-signed by at least `t` existing coordinators.
4. If threshold still cannot be re-established, poll remains `close_pending`/`stalled` (explicit state), not force-decrypted.

## Data structure deltas

### Poll metadata (`schemaVersion: 4`)

```json
{
  "schemaVersion": 4,
  "threshold": { "n": 5, "t": 4 },
  "coordinators": [
    {
      "index": 1,
      "address": "0x...",
      "encPubKey": "0x...",
      "signingPubKey": "0x...",
      "endpoint": "https://..."
    }
  ],
  "pkCommittee": "0x...",
  "dkgTranscriptRoot": "0x..."
}
```

### Tally artifact (`schemaVersion: 4`)

```json
{
  "pollId": "...",
  "schemaVersion": 4,
  "aggregate": [{ "A": "0x...", "B": "0x..." }],
  "selectedCoordinators": [1, 2, 4, 5],
  "partials": [
    {
      "coordinatorIndex": 1,
      "partial": [{ "D": "0x..." }],
      "proof": "base64",
      "signature": "0x..."
    }
  ],
  "tallies": [0, 0, 0, 0, 0, 0, 0, 0],
  "decryptProof": "base64",
  "circuitName": "combinedDecrypt_8_t4"
}
```

## Migration

- v3 polls continue and close under v3 single-key rules.
- v4 polls require threshold metadata and coordinator workflow.
- No in-place upgrade for active polls.

## Rationale summary

- **Pedersen DKG** removes dealer key-retention risk.
- **Creator-picked coordinators** is the minimum UX change and aligns with current creation flow.
- **`t = ceil(2n/3)`** balances Byzantine tolerance and liveness.
- **`schemaVersion: 4`** gives explicit parser/version separation for safe backward handling.

## References

- `docs/homomorphic-tally-spec.md`
- Helios 3.0 protocol documentation
- MACI v1 threshold decryption design notes
