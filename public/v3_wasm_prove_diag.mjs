// Reproduce the browser's WASM prove path in Node so we can
// instrument it without Playwright. Loads cs/pk/vk from the
// keystore-on-disk bytes (same paths the /api/keys endpoint
// serves), then loadKeys + prove against the dumped witness.
//
// Run:
//   node public/v3_wasm_prove_diag.mjs <keys-dir>
// e.g.
//   node public/v3_wasm_prove_diag.mjs /tmp/bitwrap-keys-debug

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const keysDir = process.argv[2] || '/tmp/bitwrap-keys-debug';

// Load the wasm runtime + bundle.
const execText = readFileSync(join(here, 'wasm_exec.js'), 'utf8');
new Function(execText)();
const go = new globalThis.Go();
const wasmBytes = readFileSync(join(here, 'prover.wasm'));
const { instance } = await WebAssembly.instantiate(wasmBytes, go.importObject);
go.run(instance);
await new Promise((r) => setImmediate(r));

const api = globalThis.bitwrapProver;
if (!api) throw new Error('bitwrapProver not exported');

// Load cs/pk/vk from disk (same bytes as /api/keys/...)
const csBytes = new Uint8Array(readFileSync(join(keysDir, 'voteCastHomomorphic_8.cs')));
const pkBytes = new Uint8Array(readFileSync(join(keysDir, 'voteCastHomomorphic_8.pk')));
const vkBytes = new Uint8Array(readFileSync(join(keysDir, 'voteCastHomomorphic_8.vk')));

console.log(`cs=${csBytes.length}B pk=${pkBytes.length}B vk=${vkBytes.length}B`);

const lk = api.loadKeys('voteCastHomomorphic_8', csBytes, pkBytes, vkBytes);
if (lk && lk.error) throw new Error('loadKeys: ' + lk.error);
console.log('loadKeys OK:', JSON.stringify(lk));

// Load the witness dumped by e2e/v3_dump_witness.spec.js.
const dump = JSON.parse(readFileSync('/tmp/v3-witness-dump.json', 'utf8'));
console.log(`witness fields: ${Object.keys(dump.witness).length}`);

const t0 = Date.now();
const result = api.prove('voteCastHomomorphic_8', JSON.stringify(dump.witness));
const elapsed = Date.now() - t0;
if (result && result.error) {
    console.error(`prove FAILED in ${elapsed}ms:`, result.error);
    process.exit(1);
}
console.log(`prove OK in ${elapsed}ms`);
console.log('proof bytes:', result.proof ? result.proof.length : 'n/a');
console.log('publicWitness bytes:', result.publicWitness ? result.publicWitness.length : 'n/a');
process.exit(0);
