// Cheap smoke test: load public/prover.wasm in Node and confirm the
// new v3 circuit names route through circuitByName. We invoke
// loadVerifyOnly with throwaway VK bytes — the deserializer will
// always fail, but the "unknown circuit: X" branch fires *before*
// deserialization, so a circuit that's not registered surfaces as a
// distinguishable error.
//
// Run: node public/prover_wasm_circuits_smoke.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

// Load wasm_exec.js into the global scope (it expects classic-script
// globals like `globalThis.Go`).
const execText = readFileSync(join(here, 'wasm_exec.js'), 'utf8');
new Function(execText)();

const go = new globalThis.Go();
const wasmBytes = readFileSync(join(here, 'prover.wasm'));
const { instance } = await WebAssembly.instantiate(wasmBytes, go.importObject);
go.run(instance); // fires-and-forgets; the bitwrapProver global is set synchronously during run

// Wait one tick so the global gets set (Go's main writes it during init).
await new Promise((r) => setImmediate(r));

const api = globalThis.bitwrapProver;
if (!api) {
    console.error('bitwrapProver not exported from wasm');
    process.exit(1);
}

let failures = 0;
function check(name) {
    const r = api.loadVerifyOnly(name, new Uint8Array([0, 0]));
    const errStr = r && r.error ? String(r.error) : '';
    if (errStr.includes('unknown circuit')) {
        console.error(`FAIL: ${name} not registered (error: ${errStr})`);
        failures++;
        return;
    }
    // Any other error is fine — it means the dispatch reached the
    // VK-deserialization step, proving the name was recognized.
    console.log(`OK:   ${name} dispatches (${errStr || 'no error?'})`);
}

check('voteCastHomomorphic_8');
check('tallyDecrypt_8');

// Sanity: pre-existing names still dispatch.
check('voteCast');
check('tallyProof_16');

if (failures > 0) {
    console.error(`\n${failures} smoke check(s) FAILED`);
    process.exit(1);
}
console.log('\nAll prover.wasm circuit dispatches OK.');
process.exit(0);
