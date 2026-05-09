// Unit tests for sk-creator-store.js. Pure-data paths only — the
// download flow is DOM-bound and exercised by the Playwright E2E in
// B5.10. Run: node public/sk_creator_store_test.mjs

import { SUBGROUP_ORDER } from './pedersen.js';
import {
    generateSkCreator,
    derivePkCreator,
    saveSkCreator,
    loadSkCreator,
    clearSkCreator,
    makeSkBackupPayload,
    parseSkBackupText,
    makeMemoryStorage,
} from './sk-creator-store.js';

let failures = 0;
function ok(cond, msg) {
    if (!cond) { console.error('FAIL:', msg); failures++; }
    else console.log('OK:  ', msg);
}
function eq(got, want, msg) {
    if (got !== want) {
        console.error(`FAIL: ${msg}\n     got:  ${got}\n     want: ${want}`);
        failures++;
    } else console.log('OK:  ', msg);
}

// 1. generateSkCreator returns a BigInt in [0, ℓ).
{
    const sk = generateSkCreator();
    ok(typeof sk === 'bigint', 'generateSkCreator returns BigInt');
    ok(sk >= 0n && sk < SUBGROUP_ORDER, 'sk is in [0, ℓ)');
}

// 2. Two consecutive generations differ (CSPRNG, not stub).
{
    const a = generateSkCreator();
    const b = generateSkCreator();
    ok(a !== b, 'two generations differ');
}

// 3. derivePkCreator returns a 32-byte (64-hex-char) compressed hex string.
{
    const sk = generateSkCreator();
    const pk = derivePkCreator(sk);
    eq(pk.length, 64, 'pk is 32 bytes (64 hex chars)');
    ok(/^[0-9a-f]+$/.test(pk), 'pk is lowercase hex');
}

// 4. save/load roundtrip.
{
    const storage = makeMemoryStorage();
    const sk = 0xfeedfacecafebeef0123456789abcdefn;
    saveSkCreator('poll-1', sk, storage);
    const loaded = loadSkCreator('poll-1', storage);
    ok(loaded === sk, 'save/load roundtrip');

    // distinct poll
    ok(loadSkCreator('poll-2', storage) === null, 'unrelated poll returns null');
}

// 5. load returns null on absent / malformed entries.
{
    const storage = makeMemoryStorage();
    ok(loadSkCreator('nope', storage) === null, 'absent returns null');
    storage.setItem('bitwrap-sk-creator-junk', 'not-a-bigint');
    ok(loadSkCreator('junk', storage) === null, 'malformed returns null');
}

// 6. clearSkCreator removes the entry.
{
    const storage = makeMemoryStorage();
    saveSkCreator('p', 42n, storage);
    clearSkCreator('p', storage);
    ok(loadSkCreator('p', storage) === null, 'clear removes entry');
}

// 7. makeSkBackupPayload + parseSkBackupText roundtrip.
{
    const sk = generateSkCreator();
    const pk = derivePkCreator(sk);
    const payload = makeSkBackupPayload('poll-abc', sk, pk);
    const text = JSON.stringify(payload);
    const parsed = parseSkBackupText(text);
    eq(parsed.pollId, 'poll-abc', 'parsed pollId');
    ok(parsed.sk === sk, 'parsed sk matches');
    eq(parsed.pkHex, pk, 'parsed pkHex matches');
}

// 8. parseSkBackupText rejects mismatched sk/pk (tamper detection).
{
    const sk = generateSkCreator();
    const pk = derivePkCreator(sk);
    const altSk = generateSkCreator(); // different key
    const tampered = JSON.stringify({
        format: 'bitwrap-sk-creator',
        version: 1,
        pollId: 'poll-x',
        sk: altSk.toString(10),
        pkCreator: pk, // belongs to the original sk, not altSk
    });
    let threw = false;
    try { parseSkBackupText(tampered); }
    catch (e) {
        threw = true;
        ok(/G·sk/.test(e.message), 'tampered file rejected with G·sk message');
    }
    ok(threw, 'tampered file throws');
}

// 9. parseSkBackupText rejects unknown format / version.
{
    let threw = false;
    try { parseSkBackupText('{"format":"other-format"}'); }
    catch { threw = true; }
    ok(threw, 'rejects unknown format');

    threw = false;
    try {
        parseSkBackupText(JSON.stringify({
            format: 'bitwrap-sk-creator', version: 999,
            pollId: 'p', sk: '1', pkCreator: 'x',
        }));
    } catch { threw = true; }
    ok(threw, 'rejects unknown version');
}

// 10. parseSkBackupText handles missing fields.
{
    let threw = false;
    try { parseSkBackupText(JSON.stringify({ format: 'bitwrap-sk-creator', version: 1 })); }
    catch (e) {
        threw = true;
        ok(/required fields/.test(e.message), 'missing-fields error message');
    }
    ok(threw, 'rejects missing fields');
}

if (failures > 0) {
    console.error(`\n${failures} check(s) FAILED`);
    process.exit(1);
}
console.log('\nAll sk-creator-store checks passed.');
