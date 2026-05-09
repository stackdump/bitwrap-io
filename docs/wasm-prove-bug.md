# gnark cs+pk serialization round-trip bug across architectures

**Status:** open. Localized but not fixed.
**Surfaced:** Phase B / B5.11 (commit `19a6453`).
**Impact:** v3 (homomorphic-tally) polls cannot complete the vote / close
flow in a browser. Privacy contract is unaffected — the server-side
lifecycle works end-to-end and the disk-leakage acceptance test
(`internal/server/v3_disk_test.go`) passes.

## TL;DR

A gnark `r1cs.R1CS` constraint system serialized via `cc.CS.WriteTo`
on 64-bit native Go (amd64 / arm64) is not byte-equivalent to the
same circuit serialized on 32-bit wasm32. Loading the native bytes
into a wasm32 prover and calling `groth16.Prove` against a witness
that satisfies the circuit produces a constraint-not-satisfied error
mid-execution. Compiling the same circuit fresh inside wasm32 and
proving with the same witness succeeds.

The bug surfaces specifically in the `scalarMulFakeGLV` hint output
binding — the in-circuit value computed from the loaded cs+pk
diverges from the witness's claimed ElGamal ciphertext component
even though the same arithmetic on the same scalar in the same
hint function on a freshly-compiled cs gives the right answer.

## Reproduction

Prerequisites:

- `bitwrap` built with v3 circuits registered in the keystore
  (default since B5.11). Run with `-key-dir <dir>` so cs/pk/vk are
  persisted.
- Node ≥ 18 to run the WASM diag scripts.

```sh
make wasm && make build
./bitwrap -dev -key-dir /tmp/bitwrap-keys-debug
```

In another shell, harvest a real browser witness to disk:

```sh
cd e2e
BASE_URL=http://localhost:8088 npx playwright test --project=v3 -g "dump"
# writes /tmp/v3-witness-dump.json
```

Then run two parallel diagnostics:

```sh
# A. WASM, loadKeys path (FAILS at constraint #2459)
node public/v3_wasm_prove_diag.mjs /tmp/bitwrap-keys-debug

# B. WASM, compileCircuit path (SUCCEEDS, ~2.5min compile + prove)
node public/v3_wasm_compile_prove_diag.mjs

# C. Native Go with the same witness (SUCCEEDS)
go test ./prover/ -run TestProveFromDumpedWitness -v

# D. Native Go, full serialize → deserialize → prove round-trip (SUCCEEDS)
go test ./prover/ -run TestCSRoundTripNativeProve -v

# E. Native + -tags=purego (same fr backend wasm uses, SUCCEEDS)
go test -tags=purego ./prover/ -run TestProveFromDumpedWitness -v
```

The combination "(A) fails while (B) (C) (D) (E) all succeed" pins
the bug to native-Go-produced cs+pk bytes being misinterpreted by
the wasm32 deserializer.

## What's been ruled out

| Hypothesis | Evidence |
|---|---|
| JS witness shape is wrong | (C) passes with the exact JS-built witness |
| Witness factory bug | Same `buildVoteCastHomomorphic8Assignment` runs in (A) and (C); (C) passes |
| Byte format unstable | (D) round-trips natively, identical bytes in/out |
| pure-Go vs asm fr arithmetic | (E) passes with `-tags=purego`, which selects the same `element_purego.go` backend wasm uses |
| Hint IDs differ across builds | `TestHintIDsNative` + WASM hint dump produce identical FNV-32a hashes (halfGCD=726531982, scalarMulHint=1399717548, decomposeScalar=1582912298) |
| Hint registration missing in WASM | gnark's `init()` runs in wasm32 the same as native; verified via instrumentation |
| Constraint count differs | Both native and WASM report 72253 constraints / 39 public / 58 secret variables for the same circuit |

## Where the bug lives (best guess)

The constraint system serialization in
`gnark@v0.14.0/constraint/marshal.go` writes:

- A header (4 × `uint64` LE)
- A levels block (`[]uint32` lengths + intcomp-packed uint32 deltas)
- An instructions block (4 parallel `[]uint32` / `[]uint64` slices,
  intcomp-packed)
- A calldata block (`uint64` length + `binary.AppendUvarint`-encoded
  uint32 wire indices)
- A CBOR-serialized body (everything else — coefficients, public/
  secret variable count, etc.)

All values are explicitly typed (`uint32`, `uint64`) — no naked
`int` is written. The intcomp library is pure Go with no asm. CBOR
is portable. So at first read this should be arch-independent.

But: `gnark@v0.14.0/constraint/r1cs.go` and the per-curve `system.go`
files have a number of fields stored as `int` in memory (not just
during serialization). When a CBOR struct includes an `int` field,
`fxamacker/cbor` writes it using the platform's int width — `int64`
on 64-bit, `int32` on 32-bit. Reading a 64-bit-encoded int into a
32-bit struct could either error out or silently truncate, depending
on the value.

Most field values fit in 32 bits (constraint counts, wire indices),
so truncation wouldn't trip. But CBOR's tagged-encoding scheme
records the size of each integer, and a value that fits in `int32`
gets a different on-wire encoding than the same value tagged as
`int64`. The reader's struct binding might then mis-thread fields
when the encoded sizes don't line up with what the local arch's
struct expects.

A targeted fix in gnark would be to mark every serialized `int` as
`int64` (or `uint64`) explicitly, so encoding is identical regardless
of the writer's word size.

## Remediation options

In rough order of effort:

1. **Document and live with it.** v3 close happens on a server-side
   context, not in a voter's browser. Fine for an admin tool, awkward
   for the "creator closes their own poll from the browser" UX.

2. **Browser-side compile + cache.** Have the WASM worker call
   `compileCircuit('voteCastHomomorphic_8')` on first use (~2.5min)
   and persist the resulting cs/pk/vk bytes to IndexedDB. Subsequent
   sessions reload from IndexedDB. The catch: those keys are
   *different* from the server's (Setup is randomized), so the
   server's verifying key won't accept proofs against them. Either
   the server has to *also* fetch and trust the browser-compiled vk,
   or both sides need to agree on a canonical setup ceremony output.

3. **Cross-compile the keystore.** Add a build step that compiles
   v3 circuits with `GOOS=js GOARCH=wasm` and writes those bytes
   to disk for `/api/keys` to serve. The wasm-flavored bytes
   round-trip cleanly in wasm. Server still uses 64-bit-native bytes
   for its own verify path. Two key directories, twice the disk,
   but fully transparent to clients.

4. **File a gnark issue and wait.** Upstream knows the codebase. If
   they confirm the int-width hypothesis a 1-line fix in marshal.go
   probably resolves it.

## Reproduction artifacts in this repo

| File | Purpose |
|---|---|
| `e2e/v3_dump_witness.spec.js` | Capture a real browser-built witness to `/tmp/v3-witness-dump.json` |
| `prover/witness_v3_dumpfile_test.go` | Native Go: replay dumped witness against a freshly compiled circuit (passes) |
| `prover/cs_roundtrip_test.go` | Native Go: full serialize → deserialize → prove (passes) |
| `prover/hint_ids_test.go` | Print hint IDs for cross-platform comparison |
| `public/v3_wasm_prove_diag.mjs` | Node-WASM: replay `loadKeys` + `prove` (fails) |
| `public/v3_wasm_compile_prove_diag.mjs` | Node-WASM: bypass `loadKeys` with fresh `compileCircuit` (succeeds) |

These run independently of Playwright/CI and produce comparable
output, so a future debugging session (or an upstream issue
reporter) can re-exercise each leg of the diagnosis without
rebuilding the whole stack.

## Pointers

- gnark serialization layer: `gnark@v0.14.0/constraint/marshal.go`,
  `internal/backend/ioutils/intcomp.go`
- gnark hint registry: `gnark@v0.14.0/constraint/solver/hint.go`
- BabyJubJub in-circuit scalar mul: `gnark@v0.14.0/std/algebra/native/twistededwards/point.go` (`scalarMulFakeGLV`)
- Off-circuit scalar mul (used by `scalarMulHint`):
  `gnark-crypto@v0.19.2/ecc/bn254/twistededwards/point.go`
  (`scalarMulWindowed` on `PointExtended`)
- bitwrap-side endpoints: `internal/server/server.go` (`handleKeys`),
  `internal/server/keys_endpoint_test.go`
- bitwrap-side witness adaptor: `prover/witness_v3_assignment.go`,
  `prover/service.go::CreateAssignment`
