# Postmortem: v3 Solidity verifier "ProofInvalid()" failures

**Status:** **fixed** in commit landing this doc. Originally tracked as #6.
**Real root cause:** public-input ordering mismatch in
`bundle_v3.go` and `v3_verifier_solidity_test.go` — both fed the
ciphertext `(A, B)` pairs to the verifier interleaved per-index when
gnark's circuit declaration walks them as sequential `CtA[0..7]` then
`CtB[0..7]` blocks.

This document is preserved as a postmortem because the original
diagnosis (committed as commit `a803e3b`, attached to issue #6) had
the wrong root cause and pointed at gnark's commitment-scheme
machinery. Future-you should not chase that thread again.

## What actually happened

`internal/server/bundle_v3.go::verifyTallyDecryptProof` built the
input array as:

```solidity
for (uint256 i = 0; i < 8; i++) {
    Ciphertext memory ct = aggregateCiphertexts[i];
    input[idx++] = ct.ax;  // A[i].x
    input[idx++] = ct.ay;  // A[i].y
    input[idx++] = ct.bx;  // B[i].x  ← wrong slot
    input[idx++] = ct.by;  // B[i].y  ← wrong slot
}
```

The same interleaved pattern lived in
`v3_verifier_solidity_test.go::buildVotePublicInputs` and
`buildTallyPublicInputs`. So the harness fed proofs and inputs that
matched each other but neither matched what the gnark-emitted
verifier expected.

gnark walks struct fields depth-first in declaration order. For:

```go
type TallyDecryptCircuit_8 struct {
    PkCreator tedwards.Point                          `gnark:",public"`
    A         [TallyDecryptChoices]tedwards.Point     `gnark:",public"`
    B         [TallyDecryptChoices]tedwards.Point     `gnark:",public"`
    Tallies   [TallyDecryptChoices]frontend.Variable  `gnark:",public"`
    ...
}
```

the public-witness layout is:

```
input[0..1]   = PkCreator{X, Y}
input[2..17]  = A[0..7]{X, Y}     ← all A's first as one block
input[18..33] = B[0..7]{X, Y}     ← then all B's
input[34..41] = Tallies[0..7]
```

Confirmed empirically in `prover/public_input_order_test.go`. The
fix is one block per array — pull `A[i]` out in a loop, then
`B[i]` in a separate loop, then `Tallies`.

## Wrong things I chased before getting here

1. **Commitment scheme handling.** The proof bytes are 324 bytes vs
   the canonical 256, so I assumed gnark was adding commitment data
   the auto-exported verifier didn't handle. Actually
   `proof.Commitments` is empty `[]` and `proof.CommitmentPok` is
   identity — the 68 extra bytes are just empty trailers from the
   proof writer encoding empty fields. Verified by reflecting into
   the `Proof` struct.
2. **Hint-free circuits.** Tried replacing `curve.ScalarMul`
   (which uses `scalarMulFakeGLV` hints) with hand-rolled
   double-and-add. Didn't help — `api.ToBinary` itself uses
   `NewHint` so the proof shape was unchanged. (And the hint vs
   commitment connection was a red herring anyway.)
3. **`backend.WithProverHashToFieldFunction(sha256.New())`.**
   Found in gnark docs as a precondition for Solidity-compatible
   commitment proofs. Tried it; produced byte-identical proofs.
   (Would have mattered for circuits that actually use commitments;
   ours don't.)

## How the bug stayed hidden

The mock-verifier path in `solidity/testgen.go:69-79` always returns
`true`, so the Foundry e2e for v1/v2 voteCast never exercised the
real verifier. v3 added a real-verifier test from day one
(`internal/server/v3_verifier_solidity_test.go`) but I gated it
under `t.Skip` when the public-input order failure produced
`ProofInvalid()` — masking a 30-line fix as an upstream gnark
limitation for several days.

## Lessons

- **The auto-exported gnark Solidity verifier works.** Every commit
  before this fix that suggested otherwise was wrong.
- **gnark's struct walk order matters.** When constructing public
  inputs for a Solidity verifier, build them by walking the struct
  fields in declaration order — never by intuition about what
  groups "look related".
- **Skipping a test that fails for a confidently-wrong reason is
  worse than leaving it failing.** Future-me: if a test fails with
  a confusing error and the fix theory is bigger than the test
  itself, the theory is probably wrong.

## Reproduction artifacts retained

- `prover/public_input_order_test.go` — prints the canonical
  public-witness order for both v3 circuits. Useful regression
  coverage if either circuit's struct shape ever changes.

## Related issue

Closed: #6. The on-chain v3 settlement story now works end-to-end
through the auto-exported gnark verifier with no upstream
dependencies.
