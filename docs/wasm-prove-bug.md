# gnark-crypto twistededwards.PointExtended.Add missing curve-params init

**Status:** worked around in-process. No fork of gnark-crypto needed.
**Workaround:** one-line `_ = babyjubjub.GetEdwardsCurve()` at the top of
`cmd/prover-wasm/main.go::main` to arm the package-level `sync.Once`.
**Regression check:** `make test-wasm-prove` (and the subprocess-isolated
`prover/wasm32_loadkeys_only_test.go`).
**Surfaced:** Phase B / B5.11 (commit `19a6453`).

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
`r1cs.Solve`:

```
scalarMulHint
  → babyjubjub.PointAffine.ScalarMultiplication
  → PointExtended.scalarMulWindowed
  → PointExtended.Add  (reads curveParams.D, never initialised)
```

`curveParams.D == 0` zeroes out the cross-term, the in-circuit
`scalarMulFakeGLV` cross-check fires:

```
constraint #2459 is not satisfied:
  1 ⋅ 2206135835295902794146583415730252686447718839502312722837270752407077685424
   != 16794912830547356530447244331793267724748168553544916545917482353364877864433
```

Server-side the bug is invisible: `frontend.Compile` runs at startup
and reaches `std/algebra/native/twistededwards.NewEdCurve`, which calls
gnark-crypto's `GetEdwardsCurve`, tripping `initOnce.Do` long before any
prove. The wasm32-vs-native framing in earlier versions of this doc
was a red herring; the bug applies to amd64 just as much, but no
production amd64 client of bitwrap loads keys without first compiling.
The subprocess regression test `prover/wasm32_loadkeys_only_test.go`
exhibits the bug on amd64 if you remove the `_ = babyjubjub.GetEdwardsCurve()`
line from inside it.

## Hypotheses ruled out (the chase)

| Hypothesis | Evidence |
|---|---|
| Cross-arch CBOR int width | Native and wasm32 produce **byte-identical** cs bytes for both `mint` and `voteCastHomomorphic_8` (`public/v3_wasm_export_diag.mjs` + `prover/wasm_export_diag_test.go`) |
| Wasm-side deserializer is lossy | Round-trip in wasm yields byte-identical bytes (`public/wasm_roundtrip_diag.mjs`) |
| Bug is generic to wasm32 prove | (A) succeeds for `mint` (no scalarMulFakeGLV); only v3 circuits fail (`public/wasm_load_native_diag.mjs mint` vs `voteCastHomomorphic_8`) |
| Bug is in cs serialization | `reflect.DeepEqual` between fresh-compile and load-from-bytes cs reports diffs only in compile-only fields (`mCoeffs`, `lbWireLevel`); rebuilding those by hand inside wasm did not fix prove |
| Bug is in pk or vk | Round-tripped pk/vk are byte-identical and reflect-equal across every G1Affine / G2Affine / Domain field |
| Bug is in unexported state of cs | Loaded-cs + fresh-Setup pk also fails; copying any single `cbor:"-"` field from a fresh compile fixes it; merely calling `frontend.Compile` *before* prove fixes it; the trigger is anything that touches the package-level `curveParams` first |

## Workaround

Apply once at process startup, before any prove. The cost is one
`sync.Once.Do` and a value-copy of a `CurveParams` struct.

```go
import (
    babyjubjub "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

func main() {
    // Tickle gnark-crypto's lazy curve-params init.
    _ = babyjubjub.GetEdwardsCurve()

    // ... rest of init ...
}
```

In bitwrap-io this lives at the top of
[`cmd/prover-wasm/main.go::main`](../cmd/prover-wasm/main.go). The Go
binary doesn't need it — `frontend.Compile` runs during server startup
and arms the `sync.Once` for the rest of the process — but it would be
correct (and harmless) to add it anywhere a prove path could run before
a compile.

## Possible upstream fix (for reference)

If you ever want to push the fix to Consensys, the change is one line
on top of the v0.19.2 generator template at
`gnark-crypto/internal/generator/edwards/template/point.go.tmpl`,
function `(*PointExtended).Add`:

```go
func (p *PointExtended) Add(p1, p2 *PointExtended) *PointExtended {
	initOnce.Do(initCurveParams)

	var A, B, C, D, E, F, G, H, tmp fr.Element
	...
}
```

Then regenerate per-curve. We're not maintaining a fork — the
in-process workaround is a smaller surface to own.

## Reproduction artifacts in this repo

| File | Purpose |
|---|---|
| `e2e/v3_dump_witness.spec.js` | Capture a real browser-built witness to `/tmp/v3-witness-dump.json` |
| `prover/witness_v3_dumpfile_test.go` | Native Go: replay dumped witness against a freshly compiled circuit (passes) |
| `prover/cs_roundtrip_test.go` | Native Go: full serialize → deserialize → prove (passes) |
| `prover/hint_ids_test.go` | Print hint IDs for cross-platform comparison |
| `prover/wasm_export_diag_test.go` | Native Go: dump cs/pk/vk for any registered circuit |
| `prover/wasm_keys_native_load_test.go` | Native Go: prove + verify against wasm-Setup keys |
| `prover/wasm32_loadkeys_only_test.go` | Native Go subprocess: load-keys-then-prove with the workaround line; remove the workaround line to reproduce the bug on amd64 |
| `public/v3_wasm_prove_diag.mjs` | Node-WASM: replay `loadKeys` + `prove` against a server keystore |
| `public/v3_wasm_compile_prove_diag.mjs` | Node-WASM: bypass `loadKeys` with fresh `compileCircuit` |
| `public/v3_wasm_export_diag.mjs` | Node-WASM: compile a circuit and dump cs/pk/vk bytes |
| `public/wasm_load_native_diag.mjs` | Node-WASM: load native cs/pk/vk bytes and prove (the canonical regression test) |
| `public/wasm_load_wasm_diag.mjs` | Node-WASM: load wasm-Setup cs/pk/vk bytes and prove |
| `public/wasm_roundtrip_diag.mjs` | Node-WASM: load native bytes, re-export, byte-diff |

## Pointers

- Buggy function: `gnark-crypto@v0.19.2 ecc/bn254/twistededwards/point.go`,
  `func (p *PointExtended) Add(p1, p2 *PointExtended) *PointExtended` —
  reads `curveParams.D` without an `initOnce.Do(initCurveParams)`
- Same template generates the same bug for every other curve under
  `gnark-crypto/ecc/*/twistededwards/point.go`
- Generator template:
  `gnark-crypto/internal/generator/edwards/template/point.go.tmpl`
- Off-circuit hint that surfaces the bug:
  `gnark@v0.14.0/std/algebra/native/twistededwards/hints.go::scalarMulHint`
- In-circuit caller:
  `gnark@v0.14.0/std/algebra/native/twistededwards/point.go::scalarMulFakeGLV`
- bitwrap-side endpoints: `internal/server/server.go` (`handleKeys`),
  `internal/server/keys_endpoint_test.go`
