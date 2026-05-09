# Phase C Roadmap — Threshold Decryption (v3.1 / schema v4)

Tracking document for delivering threshold decryption so aggregate tallies no longer depend on a single creator secret.

**Status:** design/spec phase started. Protocol reference is [`docs/threshold-decryption-spec.md`](./threshold-decryption-spec.md).

## Why

v3.0 solved per-voter reveal leakage but still trusts one key (`sk_creator`) at close time. A compromised creator key can retrospectively decrypt every ballot. Phase C removes that single-point failure with t-of-n coordinator threshold decryption.

## Protocol reference

Full technical spec: [`docs/threshold-decryption-spec.md`](./threshold-decryption-spec.md).

Key properties:
- Voters still submit one ciphertext per choice bin and one vote proof.
- Aggregation endpoint shape stays stable (`POST /api/polls/{id}/aggregate`).
- Decrypt authority moves from one creator key to a coordinator committee.
- Close artifact includes signed partial decryptions + a combined decrypt proof.

## Work breakdown

Estimated one-engineer effort: **3–6 weeks** end-to-end, assuming existing DKG primitives/libraries are reused and only integration + protocol wiring are implemented. If Pedersen DKG must be implemented from scratch, timeline increases materially. This estimate excludes third-party security audit and cryptanalysis time.

### C1. Protocol specification + schema lock — DONE

- **Deliverable:** [`docs/threshold-decryption-spec.md`](./threshold-decryption-spec.md)
- **Decisions locked:**
  - `schemaVersion: 4`
  - Pedersen DKG (no trusted dealer)
  - default threshold policy `t = ceil(2n/3)` (default n=5,t=4)
  - EIP-191 coordinator signatures

### C2. v4 schema + storage surfaces

- Add v4 poll metadata:
  - `threshold {n,t}`
  - coordinator list + coordinator public share bindings
  - committee encryption key + DKG transcript commitment
- Add v4 tally artifact fields:
  - selected coordinator set
  - per-coordinator signed partials
  - combined decrypt proof metadata
- Keep v1/v2/v3 readers and storage paths unchanged.

### C3. Coordinator cryptography primitives

- DKG transcript types, validation, and deterministic hash commitments.
- Partial decryption generation and local verifier helper.
- Lagrange-in-exponent recombination helper for aggregate decrypt.
- Golden vectors for Go↔JS parity where applicable.

### C4. New circuit family

- `PartialDecryptCircuit_K` (coordinator-side proof of correct partial).
- `CombinedDecryptCircuit_K_t` (combiner proof over selected partials + final tallies).
- Register circuits in `prover/circuits.go`; add key export and VK endpoints.
- Add refusal tests: wrong share key, wrong partial, duplicate coordinator, wrong Lagrange set, out-of-range tally.

### C5. Server/API integration

- v4-aware poll creation flow and persistence.
- `/api/polls/{id}/aggregate` accepts/collects coordinator partial artifacts and signatures.
- Coordinator identity checks and uniqueness enforcement.
- Tally publication and retrieval for v4 close artifacts.

### C6. Client integration (creator + coordinator)

- Creator-side v4 poll creation UX for coordinator set and threshold.
- Coordinator-side partial generation flow (CLI/subcommand or service endpoint in initial slice).
- Close-flow orchestration: collect partials, verify, combine, publish.

### C7. Liveness + operational recovery

- Retry windows (`T_close`, `T_retry`) and state transitions (`close_pending`, `stalled`).
- Coordinator replacement/re-share artifact format and quorum checks.
- No single-master-key emergency decrypt mode.

### C8. E2E + acceptance + docs

- End-to-end tests for:
  - happy-path threshold close (exactly t partials)
  - liveness with n-t offline coordinators
  - rejection of Byzantine partial/signature mismatch
  - backward-compat close for v3 polls
- Update docs and operator runbook sections.

## Not in scope for Phase C

- Dedicated coordinator web UI.
- External audit/cryptanalysis of DKG implementation.
- On-chain settlement changes beyond proof artifact compatibility.
