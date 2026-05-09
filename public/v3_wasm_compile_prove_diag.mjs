// Compile + prove voteCastHomomorphic_8 entirely in WASM (no serialized
// cs/pk fetched from the server). If THIS prove succeeds with the
// same witness that fails when keys are loaded from disk, the bug
// is in the cs/pk serialization round-trip. If this still fails,
// the bug is in gnark's WASM-side scalar mul / circuit Define run.
//
// Run: node public/v3_wasm_compile_prove_diag.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const execText = readFileSync(join(here, 'wasm_exec.js'), 'utf8');
new Function(execText)();
const go = new globalThis.Go();
const wasmBytes = readFileSync(join(here, 'prover.wasm'));
const { instance } = await WebAssembly.instantiate(wasmBytes, go.importObject);
go.run(instance);
await new Promise((r) => setImmediate(r));

const api = globalThis.bitwrapProver;
if (!api) throw new Error('bitwrapProver not exported');

console.log('compiling voteCastHomomorphic_8 fresh in WASM (slow)...');
const t0 = Date.now();
const cc = api.compileCircuit('voteCastHomomorphic_8');
if (cc && cc.error) throw new Error('compileCircuit: ' + cc.error);
console.log(`compile OK in ${Date.now() - t0}ms:`, JSON.stringify(cc));

const dump = JSON.parse(readFileSync('/tmp/v3-witness-dump.json', 'utf8'));
const t1 = Date.now();
const result = api.prove('voteCastHomomorphic_8', JSON.stringify(dump.witness));
const elapsed = Date.now() - t1;
if (result && result.error) {
    console.error(`prove FAILED in ${elapsed}ms:`, result.error);
    process.exit(1);
}
console.log(`prove OK in ${elapsed}ms`);
process.exit(0);
