# gnark `vk.ExportSolidity` emits a no-commitment verifier for circuits that produce commitment-bearing proofs

**Status:** open. Localized but not fixed. Affects every Groth16 circuit in this repo.
**Surfaced:** Phase B / B5.10c (issue #6 originally).
**Impact:** Auto-exported Solidity verifiers reject valid proofs. On-chain settlement of bitwrap polls — v1, v2, *and* v3 — is currently broken end-to-end via the auto-export path. The `solidity/testgen.go` test harness papers over this with a `MockVerifier` that always returns `true`.

## TL;DR

gnark's Groth16 proof writer adds commitment-scheme data (1 G1 commitment + 1 G1 commitmentPok = 64 bytes + a 4-byte length prefix = 68 extra bytes, taking proofs from 256 to 324 raw bytes) for any circuit that uses `api.Compiler().NewHint`. That includes `api.ToBinary`, which is required by any real ECC scalar mul, which means **every circuit in this repo emits 324-byte proofs**.

Meanwhile, gnark's `vk.ExportSolidity` template gates commitment-aware code paths on `{{- if gt $numCommitments 0 }}` — and for these circuits `numCommitments` is reported as 0, so the emitted Solidity verifier has only `verifyProof(uint256[8] proof, uint256[N] input)` with no slot for commitment data. The verifier's pairing equation can't account for the commitment, so it rejects every proof with `ProofInvalid()`.

The mismatch isn't between v1/v2 and v3 — it's between gnark's proof writer and gnark's verifier exporter, and it affects everything.

## Reproduction

Add a small Go test that compiles each circuit and measures the raw proof bytes:

```go
proof, _ := groth16.Prove(cc.CS, cc.ProvingKey, witness)
var raw bytes.Buffer
proof.WriteRawTo(&raw)
fmt.Printf("%d bytes (%d field elements)\n", raw.Len(), raw.Len()/32)
```

Observed:

```
voteCast (v1/v2):              15261 constraints, raw proof = 324 bytes (10 field elements)
voteCastHomomorphic_8:         72253 constraints, raw proof = 324 bytes (10 field elements)
tallyDecrypt_8:                40958 constraints, raw proof = 324 bytes (10 field elements)
```

Inspect each emitted Solidity verifier:

```sh
curl -s http://localhost:8088/api/vk/voteCast/solidity                | grep "function verifyProof"
curl -s http://localhost:8088/api/vk/voteCastHomomorphic_8/solidity   | grep "function verifyProof"
curl -s http://localhost:8088/api/vk/tallyDecrypt_8/solidity          | grep "function verifyProof"
```

All three emit a single signature `verifyProof(uint256[8] calldata proof, uint256[N] calldata input)` — no `commitments[]` parameter. The "we reduce commitments(if any)" comment shows up in `publicInputMSM` but the function never actually receives commitments.

The discrepancy: proof writer adds commitment data, vk reports zero commitments, verifier emitted without commitment-handling. Pairing equation breaks.

## What's been ruled out

| Hypothesis | Evidence |
|---|---|
| v3-specific (BabyJubJub, fakeGLV hints) | v1/v2 voteCast also produces 324-byte proofs |
| Hint type matters (user vs stdlib) | Replacing `curve.ScalarMul` (which uses GLV-style hints) with hand-rolled double-and-add (using only `Add`, `Double`, `ToBinary`) still produces 324-byte proofs — `ToBinary` itself triggers commitments via `gnark/std/math/bits/conversion_binary.go:125` |
| Test harness encoding bug | The Foundry harness wired up by PR #9 was confirmed correct; the verifier itself reverts with `ProofInvalid()` |
| v1/v2 was working with the auto-exported verifier | `solidity/testgen.go:69-79` generates a `MockVerifier` returning `true`; `internal/server/foundry_e2e_test.go` uses it. The auto-exported verifier has never been exercised in this repo. |

## Where the bug lives

**Upstream in gnark.** Specifically:

- `frontend/cs/r1cs/builder.go` — when the r1cs builder encounters `NewHint` calls, it should register the hint outputs as committed values in the constraint system metadata. The proof writer ([`backend/groth16/bn254/marshal.go:33-56`](https://github.com/Consensys/gnark/blob/master/backend/groth16/bn254/marshal.go)) then attaches them as `Commitments` + `CommitmentPok` regardless of vk metadata.
- `backend/groth16/bn254/solidity.go:39` — the template gates commitment-aware code on `numCommitments > 0` from the vk's perspective.

These two view of `numCommitments` should agree. They don't. Either:
- The r1cs builder is failing to mark hint-bearing constraint systems as commitment-bearing (likely);
- Or the proof writer is over-eagerly adding commitments to proofs that genuinely have no commitment metadata (less likely — would break verify too).

A targeted fix in gnark would be to ensure `vk.PublicAndCommitmentCommitted` (or equivalent) gets populated whenever the cs has any hint-bearing constraints, so the Solidity exporter takes the commitment-aware code path and the emitted verifier accepts the extra 68 bytes.

## Remediation paths

In rough order of effort (full discussion in the linked issue comment thread):

1. **File an upstream gnark issue.** Provide the reproduction artifacts (proof byte size + emitted verifier shape). A one-flag flip during Setup or vk export would resolve it for every circuit in this repo without further work.

2. **Custom Solidity codegen.** Stop relying on `vk.ExportSolidity` and write our own verifier template in `solidity/` that knows about gnark's actual proof shape. Higher engineering effort but cleanly de-couples from gnark's template choices. Reusable across all bitwrap circuits.

3. **snarkjs re-export.** snarkjs's Groth16-to-Solidity exporter uses a different proof shape and convention; pipe gnark's proving key through snarkjs as a build step. Adds a JS dependency to the build pipeline.

## What to update in this repo when one of those lands

- `internal/server/v3_verifier_solidity_test.go:68` — un-skip `TestHandleVKV3SolidityCompilesAndVerifiesOnChain`.
- `solidity/testgen.go:69-79` — replace `MockVerifier` with the real exported verifier in v1/v2 e2e tests.
- `README.md` — drop the "Known limitations" section that documents this gap.
- `docs/phase-b-roadmap.md` — re-open the on-chain settlement story for v3.

## Reproduction artifacts

| File | Purpose |
|---|---|
| `prover/v3_proof_layout_test.go` | Compute and print raw proof byte size for each v3 circuit |
| `internal/server/v3_verifier_solidity_test.go` | Foundry harness that compiles + runs the gnark verifier; currently `t.Skip`'d at line 68 |
| `internal/server/bundle_v3.go` | v3 governance contract showing the expected `verifyProof(uint256[8], uint256[N])` interface declaration |

## Pointers

- gnark proof writer: [`backend/groth16/bn254/marshal.go:33-56`](https://github.com/Consensys/gnark/blob/master/backend/groth16/bn254/marshal.go)
- gnark Solidity template: [`backend/groth16/bn254/solidity.go`](https://github.com/Consensys/gnark/blob/master/backend/groth16/bn254/solidity.go)
- gnark template's commitment gate: [`solidity.go:39`](https://github.com/Consensys/gnark/blob/master/backend/groth16/bn254/solidity.go) `{{- if gt $numCommitments 0 }}`
- ToBinary's hint usage: [`std/math/bits/conversion_binary.go:125`](https://github.com/Consensys/gnark/blob/master/std/math/bits/conversion_binary.go)
- bitwrap mock-verifier discovery: `solidity/testgen.go:69-79`
- bitwrap on-chain test that's skipped: `internal/server/v3_verifier_solidity_test.go:68`
