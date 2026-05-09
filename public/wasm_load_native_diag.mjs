// Load native-Go-produced cs/pk/vk into wasm and try to prove a simple
// circuit (default: mint). Pairs with `go test -run TestNativeExportKeys`
// which produces the bytes.
//
// If THIS succeeds for mint but fails for voteCastHomomorphic_8, the
// issue #3 bug is specific to circuits using scalarMulFakeGLV /
// BabyJubJub hint paths and not a generic CBOR / encoding regression.
//
// Run:
//   node public/wasm_load_native_diag.mjs <circuit>

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const name = process.argv[2] || 'mint';

const execText = readFileSync(join(here, 'wasm_exec.js'), 'utf8');
new Function(execText)();
const go = new globalThis.Go();
const wasmBytes = readFileSync(join(here, 'prover.wasm'));
const { instance } = await WebAssembly.instantiate(wasmBytes, go.importObject);
go.run(instance);
await new Promise((r) => setImmediate(r));

const api = globalThis.bitwrapProver;
if (!api) throw new Error('bitwrapProver not exported');

const csBytes = new Uint8Array(readFileSync(`/tmp/native-keys-${name}.cs`));
const pkBytes = new Uint8Array(readFileSync(`/tmp/native-keys-${name}.pk`));
const vkBytes = new Uint8Array(readFileSync(`/tmp/native-keys-${name}.vk`));

const sha = (b) => createHash('sha256').update(b).digest('hex').slice(0, 16);
console.log(`[${name}] cs=${csBytes.length}B (${sha(csBytes)}) pk=${pkBytes.length}B vk=${vkBytes.length}B`);

const lk = api.loadKeys(name, csBytes, pkBytes, vkBytes);
if (lk && lk.error) throw new Error('loadKeys: ' + lk.error);
console.log('loadKeys OK:', JSON.stringify(lk));

// Build a satisfying mint witness: mimcHash(99, 1500) using exposed mimcHash.
const witness = (() => {
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
    if (name === 'voteCastHomomorphic_8') {
        const dump = JSON.parse(readFileSync('/tmp/v3-witness-dump.json', 'utf8'));
        return dump.witness;
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
