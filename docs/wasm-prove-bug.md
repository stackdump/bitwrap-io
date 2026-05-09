# gnark wasm32 prove bug after cs deserialize

**Status:** worked-around in browser. Root cause not yet fixed upstream.
**Surfaced:** Phase B / B5.11 (commit `19a6453`).
**Workaround landed:** 2026-05-09 — `loadKeysFreshCS` in the wasm prover.
**Impact:** v3 (homomorphic-tally) polls **now** complete the vote / close
flow in a browser via the workaround. Privacy contract was unaffected
even before the workaround (server-side lifecycle works end-to-end and
`internal/server/v3_disk_test.go` enforces disk-leakage absence).

## TL;DR

A gnark `r1cs.R1CS` constraint system **deserialized** via `cs.ReadFrom`
on wasm32 produces an in-memory cs that the wasm32 prover handles
*incorrectly* for circuits using `scalarMulFakeGLV` (BabyJubJub).
Compiling the same circuit *in process* yields a cs whose bytes are
**byte-identical** to the deserialized one yet which proves correctly.
Native Go (amd64 / arm64) is unaffected — its prover handles the
deserialized cs the same as the freshly-compiled one.

So this is **not** a cross-architecture serialization bug (the bytes
are platform-independent) — it's a wasm32-specific bug somewhere in the
gnark prove path that depends on non-serialized in-memory state which
is set during `frontend.Compile` but lost on `cs.ReadFrom`.

The bug surfaces in the `scalarMulFakeGLV` hint output binding — the
in-circuit computation diverges from the hint's claimed value, even
though the same arithmetic on the same scalar in the same hint function
on a freshly-compiled cs gives the right answer.

## Workaround in production

The browser prover now exposes `loadKeysFreshCS(name, pkBytes, vkBytes)`
which **recompiles** the circuit cs in-wasm and pairs it with the
server-supplied pk/vk. v3 circuits (`voteCastHomomorphic_8`,
`tallyDecrypt_8`) use this path; everything else still goes through
the cheaper `loadKeys`. Cost is one circuit compile per session
(~50 s for `voteCastHomomorphic_8` on a modern laptop), then ~10 s
per vote / close. See:

- `cmd/prover-wasm/main.go::loadKeysFreshCS`
- `public/prover.js::loadKeysFreshCS`
- `public/poll.js::ensureV3Circuit` (FRESH_CS_CIRCUITS set)
- `public/wasm_freshcs_diag.mjs` (Node-WASM repro of the workaround)

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
| Cross-arch CBOR int width | Native and wasm32 produce **byte-identical** cs bytes for both `mint` and `voteCastHomomorphic_8` (verified via `public/v3_wasm_export_diag.mjs` + `prover/wasm_export_diag_test.go`) |
| Wasm-side deserializer is lossy | Round-trip in wasm (`load → write`) yields byte-identical bytes (`public/wasm_roundtrip_diag.mjs`) |
| pure-Go vs asm fr arithmetic | (E) passes with `-tags=purego`, which selects the same `element_purego.go` backend wasm uses |
| Hint IDs differ across builds | `TestHintIDsNative` + WASM hint dump produce identical FNV-32a hashes (halfGCD=726531982, scalarMulHint=1399717548, decomposeScalar=1582912298) |
| Hint registration missing in WASM | gnark's `init()` runs in wasm32 the same as native; verified via instrumentation |
| Constraint count differs | Both native and WASM report 72253 constraints / 39 public / 58 secret variables for the same circuit |
| Bug is generic to all wasm32 prove | (A) succeeds for `mint` (no scalarMulFakeGLV) on wasm32 with native bytes; only v3 circuits fail (`public/wasm_load_native_diag.mjs mint` vs `voteCastHomomorphic_8`) |
| Bug is specific to native→wasm cross-arch | wasm-Setup keys also fail on wasm prove (`public/wasm_load_wasm_diag.mjs voteCastHomomorphic_8`) — the bug is wasm-prove vs deserialized-cs, not native-vs-wasm |

## Where the bug lives (current understanding)

The original hypothesis was a CBOR int-width issue in
`gnark@v0.14.0/constraint/marshal.go`. That hypothesis is now **ruled
out**: `cs.WriteTo` produces byte-identical bytes on amd64 and wasm32
for both small (`mint`) and large (`voteCastHomomorphic_8`) circuits,
and a wasm-side `load → write` round-trip is also byte-identical. The
deserializer faithfully reconstructs everything that's in the bytes.

The remaining suspect is **non-serialized in-memory state of the cs
that's set during `frontend.Compile` but not by `cs.ReadFrom`**, and
which the wasm32 prover depends on while the native prover does not.
Candidates (`cbor:"-"` in `gnark@v0.14.0/constraint/core.go`):

- `lbWireLevel []Level` — only used by the level-builder during
  compile per source comments; should be irrelevant to prove.
- `q *big.Int`, `bitLen int` — both reconstructed in
  `CheckSerializationHeader`.
- `genericHint BlueprintID` — unexported, defaults to 0 from
  `NewSystem`'s implicit `AddBlueprint(&BlueprintGenericHint{})`.

A byte-level diff says nothing because the bytes match. The next
diagnostic step would be to dump every reachable field of the
in-memory cs after compile vs after load and find which one differs
on wasm32.

## Why the workaround works

`loadKeysFreshCS(name, pk, vk)` calls `frontend.Compile(...)` from
inside wasm and uses that cs object to prove. Whatever non-serialized
state the wasm prover needs is set up by `Compile` and remains in
memory throughout the prove call. The pk/vk supplied by the server
match because they were produced by `groth16.Setup` against the same
deterministic circuit definition.

## Remediation options (longer term)

In rough order of effort:

1. **Keep the workaround** (current state). Voters pay a one-time
   ~50 s circuit compile per session. UX could be improved by
   pre-compiling in a Web Worker on page load.

2. **Diff in-memory cs state** (next localization step). Walk every
   reachable field on a freshly-compiled cs and a deserialized cs
   inside wasm and report deltas. Whatever's missing is the bug.

3. **File a gnark issue / fork upstream.** Once localized, the fix
   is likely a few lines in `cs.ReadFrom` or in the prover's wasm32
   path.

## Reproduction artifacts in this repo

| File | Purpose |
|---|---|
| `e2e/v3_dump_witness.spec.js` | Capture a real browser-built witness to `/tmp/v3-witness-dump.json` |
| `prover/witness_v3_dumpfile_test.go` | Native Go: replay dumped witness against a freshly compiled circuit (passes) |
| `prover/cs_roundtrip_test.go` | Native Go: full serialize → deserialize → prove (passes) |
| `prover/hint_ids_test.go` | Print hint IDs for cross-platform comparison |
| `prover/wasm_export_diag_test.go` | Native Go: dump cs/pk/vk for any registered circuit (paired with the wasm diags) |
| `prover/wasm_keys_native_load_test.go` | Native Go: prove + verify against wasm-Setup keys (passes for `mint`; demonstrates wasm-encoded keys round-trip cleanly into native) |
| `public/v3_wasm_prove_diag.mjs` | Node-WASM: replay `loadKeys` + `prove` against a keystore (fails for v3) |
| `public/v3_wasm_compile_prove_diag.mjs` | Node-WASM: bypass `loadKeys` with fresh `compileCircuit` (succeeds) |
| `public/v3_wasm_export_diag.mjs` | Node-WASM: compile a circuit and dump cs/pk/vk bytes |
| `public/wasm_load_native_diag.mjs` | Node-WASM: load native cs/pk/vk bytes and prove (fails for v3, passes for `mint`) |
| `public/wasm_load_wasm_diag.mjs` | Node-WASM: load wasm-Setup cs/pk/vk bytes and prove (fails for v3 — shows it's not cross-arch) |
| `public/wasm_roundtrip_diag.mjs` | Node-WASM: load native bytes, re-export, byte-diff (identical — deserializer is faithful) |
| `public/wasm_freshcs_diag.mjs` | Node-WASM: the workaround — load native pk/vk, recompile cs in wasm, prove (passes) |

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
