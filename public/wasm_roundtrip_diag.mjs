// Round-trip the cs+pk+vk bytes through WASM: load native bytes, then
// re-export. Compare original vs re-exported. If they differ, the wasm
// loader is lossy — that's likely where the v3 prove failure comes from.
//
// Run after: NATIVE_EXPORT_CIRCUIT=<name> go test -run TestNativeExportKeys ./prover
//
//   node public/wasm_roundtrip_diag.mjs <circuit>

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';

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

const csIn = new Uint8Array(readFileSync(`/tmp/native-keys-${name}.cs`));
const pkIn = new Uint8Array(readFileSync(`/tmp/native-keys-${name}.pk`));
const vkIn = new Uint8Array(readFileSync(`/tmp/native-keys-${name}.vk`));

const sha = (b) => createHash('sha256').update(b).digest('hex').slice(0, 24);
console.log(`[in] cs=${csIn.length}B (${sha(csIn)}) pk=${pkIn.length}B (${sha(pkIn)}) vk=${vkIn.length}B (${sha(vkIn)})`);

const lk = api.loadKeys(name, csIn, pkIn, vkIn);
if (lk && lk.error) throw new Error('loadKeys: ' + lk.error);

const out = api.exportKeys(name);
if (out && out.error) throw new Error('exportKeys: ' + out.error);

const csOut = new Uint8Array(out.cs);
const pkOut = new Uint8Array(out.pk);
const vkOut = new Uint8Array(out.vk);
console.log(`[out] cs=${csOut.length}B (${sha(csOut)}) pk=${pkOut.length}B (${sha(pkOut)}) vk=${vkOut.length}B (${sha(vkOut)})`);

const diff = (a, b, tag) => {
    if (a.length !== b.length) {
        console.log(`${tag}: LENGTH DIFFERS (${a.length} vs ${b.length})`);
        return false;
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            console.log(`${tag}: differs at byte ${i}: in=${a[i].toString(16)} out=${b[i].toString(16)}`);
            return false;
        }
    }
    console.log(`${tag}: byte-identical (${a.length}B)`);
    return true;
};

const csOk = diff(csIn, csOut, 'cs');
const pkOk = diff(pkIn, pkOut, 'pk');
const vkOk = diff(vkIn, vkOut, 'vk');

writeFileSync(`/tmp/wasm-roundtrip-${name}.cs`, csOut);
writeFileSync(`/tmp/wasm-roundtrip-${name}.pk`, pkOut);
writeFileSync(`/tmp/wasm-roundtrip-${name}.vk`, vkOut);
console.log(`wrote /tmp/wasm-roundtrip-${name}.{cs,pk,vk}`);

if (csOk && pkOk && vkOk) {
    console.log('ALL identical — bug not in serialization round-trip');
    process.exit(0);
} else {
    console.log('serialization round-trip is LOSSY');
    process.exit(1);
}
