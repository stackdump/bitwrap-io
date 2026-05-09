# gnark-crypto twistededwards.PointExtended.Add missing curve-params init

**Status:** fixed in our gnark-crypto fork (`fix-pointextended-add-init`),
pinned via `replace` in [`go.mod`](../go.mod). Regression check is
`make test-wasm-prove`.
**Surfaced:** Phase B / B5.11 (commit `19a6453`).
**Fork landed:** 2026-05-09.

## Root cause

`gnark-crypto/ecc/<curve>/twistededwards/point.go::PointExtended.Add`
reads `curveParams.D` to compute the curve-equation cross-term, but —
unlike its `PointAffine.Add`, `PointAffine.IsOnCurve`, `PointProj.Add`,
`PointProj.MixedAdd` siblings — does **not** call
`initOnce.Do(initCurveParams)` first.

`curveParams` is a package-level `CurveParams`, lazily initialised by
`initCurveParams` via a `sync.Once`. Anything that has previously
called `GetEdwardsCurve()`, `IsOnCurve`, `PointAffine.Add`, `PointProj.Add`,
or `PointProj.MixedAdd` triggers the init. The first caller of
`PointExtended.Add` in a process that has done none of those reads
`curveParams.D == 0`, computes a wrong point, and propagates the wrong
value back through the hint output binding.

The bug is in every twisted-Edwards curve generated from
`internal/generator/edwards/template/point.go.tmpl`: bn254, bls12-377,
bls12-381 (and bandersnatch), bls24-315, bls24-317, bw6-633, bw6-761.

## Why it bit us

The bitwrap browser flow loads cs/pk/vk via `/api/keys` and never
compiles the circuit on the client. The first thing that touches
twistededwards is the BN254 `scalarMulHint` invoked during
`r1cs.Solve` — which goes:

```
scalarMulHint
  → babyjubjub.PointAffine.ScalarMultiplication
  → PointExtended.scalarMulWindowed
  → PointExtended.Add  (reads curveParams.D, never initialised)
```

`curveParams.D == 0` makes the cross-term zero, the in-circuit
`scalarMulFakeGLV` cross-check fires:

```
constraint #2459 is not satisfied:
  1 ⋅ 2206135835295902794146583415730252686447718839502312722837270752407077685424
   != 16794912830547356530447244331793267724748168553544916545917482353364877864433
```

On the server side the bug is invisible: `frontend.Compile` runs
`std/algebra/native/twistededwards.NewEdCurve` which calls
gnark-crypto's `GetEdwardsCurve`, triggering `initOnce.Do` long before
any prove starts. The wasm32-vs-native framing in earlier versions of
this doc was a red herring; the bug applies to amd64 just as much, but
no production amd64 client of bitwrap loads keys without compiling.

## Hypotheses ruled out (kept as a record of the chase)

| Hypothesis | Evidence |
|---|---|
| Cross-arch CBOR int width | Native and wasm32 produce **byte-identical** cs bytes for both `mint` and `voteCastHomomorphic_8` (`public/v3_wasm_export_diag.mjs` + `prover/wasm_export_diag_test.go`) |
| Wasm-side deserializer is lossy | Round-trip in wasm yields byte-identical bytes (`public/wasm_roundtrip_diag.mjs`) |
| Bug is generic to wasm32 prove | (A) succeeds for `mint` (no scalarMulFakeGLV); only v3 circuits fail (`public/wasm_load_native_diag.mjs mint` vs `voteCastHomomorphic_8`) |
| Bug is in cs serialization | `reflect.DeepEqual` between fresh-compile and load-from-bytes cs reports diffs only in compile-only fields (`mCoeffs`, `lbWireLevel`); rebuilding those by hand inside wasm did not fix prove |
| Bug is in pk or vk | `compareAnyObjects(freshPk, loadedPk)` and `compareAnyObjects(freshVk, loadedVk)` report zero diffs over every G1Affine / G2Affine / Domain field |
| Bug is in unexported state of cs | Loaded-cs + fresh-Setup pk also fails; copying the four `cbor:"-"` fields fixes it; isolating each field shows even an empty copy fixes it; merely calling `frontend.Compile` *before* prove fixes it; the trigger is anything that touches the package-level `curveParams` first |

## Fix

`gnark-crypto/ecc/<curve>/twistededwards/point.go`, top of
`PointExtended.Add`:

```go
func (p *PointExtended) Add(p1, p2 *PointExtended) *PointExtended {
	initOnce.Do(initCurveParams)

	var A, B, C, D, E, F, G, H, tmp fr.Element
	...
}
```

Same line in the corresponding template
`internal/generator/edwards/template/point.go.tmpl`. Patched in
[stackdump/gnark-crypto@fix-pointextended-add-init](https://github.com/stackdump/gnark-crypto/tree/fix-pointextended-add-init);
pinned in `go.mod` via the `replace` directive.

## Reproduction artifacts in this repo

| File | Purpose |
|---|---|
| `e2e/v3_dump_witness.spec.js` | Capture a real browser-built witness to `/tmp/v3-witness-dump.json` |
| `prover/witness_v3_dumpfile_test.go` | Native Go: replay dumped witness against a freshly compiled circuit (passes) |
| `prover/cs_roundtrip_test.go` | Native Go: full serialize → deserialize → prove (passes) |
| `prover/hint_ids_test.go` | Print hint IDs for cross-platform comparison |
| `prover/wasm_export_diag_test.go` | Native Go: dump cs/pk/vk for any registered circuit |
| `prover/wasm_keys_native_load_test.go` | Native Go: prove + verify against wasm-Setup keys |
| `prover/wasm32_loadkeys_only_test.go` | Native Go: load-keys-then-prove without prior compile/Setup — pre-fix this would fail; passes now |
| `public/v3_wasm_prove_diag.mjs` | Node-WASM: replay `loadKeys` + `prove` against a server keystore |
| `public/v3_wasm_compile_prove_diag.mjs` | Node-WASM: bypass `loadKeys` with fresh `compileCircuit` |
| `public/v3_wasm_export_diag.mjs` | Node-WASM: compile a circuit and dump cs/pk/vk bytes |
| `public/wasm_load_native_diag.mjs` | Node-WASM: load native cs/pk/vk bytes and prove (the canonical regression test) |
| `public/wasm_load_wasm_diag.mjs` | Node-WASM: load wasm-Setup cs/pk/vk bytes and prove |
| `public/wasm_roundtrip_diag.mjs` | Node-WASM: load native bytes, re-export, byte-diff |

## Pointers

- Patched function: `gnark-crypto@fix-pointextended-add-init` /
  `ecc/bn254/twistededwards/point.go`, function `PointExtended.Add`
- Generator template:
  `gnark-crypto/internal/generator/edwards/template/point.go.tmpl`,
  function `(*PointExtended).Add`
- Off-circuit hint: `gnark@v0.14.0/std/algebra/native/twistededwards/hints.go::scalarMulHint`
- In-circuit caller: `gnark@v0.14.0/std/algebra/native/twistededwards/point.go::scalarMulFakeGLV`
- bitwrap-side endpoints: `internal/server/server.go` (`handleKeys`),
  `internal/server/keys_endpoint_test.go`
