// Hypothesis check for issue #3: load pk/vk from native bytes, but
// re-compile the circuit cs fresh in wasm. If THIS prove succeeds where
// loadKeys() (whole-cs deserialize) fails, the bug lives in some
// non-serialized in-memory state of the cs that's set during compile but
// not reconstructed during ReadFrom on wasm32.
//
// Run: node public/wasm_freshcs_diag.mjs <circuit>

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

const pkBytes = new Uint8Array(readFileSync(`/tmp/native-keys-${name}.pk`));
const vkBytes = new Uint8Array(readFileSync(`/tmp/native-keys-${name}.vk`));
console.log(`[${name}] pk=${pkBytes.length}B vk=${vkBytes.length}B; recompiling cs fresh...`);

const t0 = Date.now();
const lk = api.loadKeysFreshCS(name, pkBytes, vkBytes);
if (lk && lk.error) throw new Error('loadKeysFreshCS: ' + lk.error);
console.log(`loadKeysFreshCS OK in ${Date.now() - t0}ms:`, JSON.stringify(lk));

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

const t1 = Date.now();
const result = api.prove(name, JSON.stringify(witness));
const elapsed = Date.now() - t1;
if (result && result.error) {
    console.error(`prove FAILED in ${elapsed}ms:`, result.error);
    process.exit(1);
}
console.log(`prove OK in ${elapsed}ms (proof=${result.proof.length}B)`);
process.exit(0);
