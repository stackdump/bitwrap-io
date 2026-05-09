// Compile a circuit fresh in WASM and dump the cs/pk/vk bytes to disk.
// Pairs with prover/wasm_export_diag_test.go which compiles the same
// circuit natively and dumps to /tmp/native-keys-<name>.{cs,pk,vk}.
//
// Run: node public/v3_wasm_export_diag.mjs <circuitName>
//
// Output: /tmp/wasm-keys-<name>.cs, /tmp/wasm-keys-<name>.pk, /tmp/wasm-keys-<name>.vk

import { readFileSync, writeFileSync } from 'node:fs';
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

const name = process.argv[2] || 'mint';
console.log(`compiling ${name} in WASM...`);
const t0 = Date.now();
const cc = api.compileCircuit(name);
if (cc && cc.error) throw new Error('compileCircuit: ' + cc.error);
console.log(`compile OK in ${Date.now() - t0}ms:`, JSON.stringify(cc));

const keys = api.exportKeys(name);
if (keys && keys.error) throw new Error('exportKeys: ' + keys.error);

const csOut = `/tmp/wasm-keys-${name}.cs`;
const pkOut = `/tmp/wasm-keys-${name}.pk`;
const vkOut = `/tmp/wasm-keys-${name}.vk`;
writeFileSync(csOut, Buffer.from(keys.cs));
writeFileSync(pkOut, Buffer.from(keys.pk));
writeFileSync(vkOut, Buffer.from(keys.vk));
console.log(`wrote ${keys.cs.length} bytes cs → ${csOut}`);
console.log(`wrote ${keys.pk.length} bytes pk → ${pkOut}`);
console.log(`wrote ${keys.vk.length} bytes vk → ${vkOut}`);
process.exit(0);
