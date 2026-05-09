// Load wasm-Setup-produced cs/pk/vk into a fresh WASM instance and try
// to prove. Confirms whether the wasm-compiled bytes round-trip cleanly
// across a save → reload cycle inside wasm — i.e., whether they are
// suitable as the canonical bytes the keystore should ship.
//
// Run after: `node public/v3_wasm_export_diag.mjs <circuit>`
//
//   node public/wasm_load_wasm_diag.mjs <circuit>

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const name = process.argv[2] || 'voteCastHomomorphic_8';

const execText = readFileSync(join(here, 'wasm_exec.js'), 'utf8');
new Function(execText)();
const go = new globalThis.Go();
const wasmBytes = readFileSync(join(here, 'prover.wasm'));
const { instance } = await WebAssembly.instantiate(wasmBytes, go.importObject);
go.run(instance);
await new Promise((r) => setImmediate(r));

const api = globalThis.bitwrapProver;
if (!api) throw new Error('bitwrapProver not exported');

const csBytes = new Uint8Array(readFileSync(`/tmp/wasm-keys-${name}.cs`));
const pkBytes = new Uint8Array(readFileSync(`/tmp/wasm-keys-${name}.pk`));
const vkBytes = new Uint8Array(readFileSync(`/tmp/wasm-keys-${name}.vk`));

console.log(`[${name}] loading wasm-Setup bytes: cs=${csBytes.length}B pk=${pkBytes.length}B vk=${vkBytes.length}B`);
const lk = api.loadKeys(name, csBytes, pkBytes, vkBytes);
if (lk && lk.error) throw new Error('loadKeys: ' + lk.error);
console.log('loadKeys OK:', JSON.stringify(lk));

const witness = (() => {
    if (name === 'voteCastHomomorphic_8') {
        return JSON.parse(readFileSync('/tmp/v3-witness-dump.json', 'utf8')).witness;
    }
    if (name === 'mint') {
        const post = api.mimcHash('99', '1500');
        return {
            preStateRoot: '0',
            postStateRoot: post,
            caller: '42',
            to: '99',
            amount: '1000',
            minter: '42',
            balanceTo: '500',
        };
    }
    throw new Error(`no witness builder for ${name}`);
})();

const t0 = Date.now();
const result = api.prove(name, JSON.stringify(witness));
const elapsed = Date.now() - t0;
if (result && result.error) {
    console.error(`prove FAILED in ${elapsed}ms:`, result.error);
    process.exit(1);
}
console.log(`prove OK in ${elapsed}ms (proof=${result.proof.length}B publicWitness=${result.publicWitness.length}B)`);
process.exit(0);
