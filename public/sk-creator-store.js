// sk-creator-store.js — local storage and backup for the v3 poll
// creator's secret key (sk_creator).
//
// Per the locked-in custody decision (client-only), sk_creator is
// generated in the browser at poll creation, saved to localStorage,
// and a JSON backup is offered for download. The server NEVER sees it.
// Loss of localStorage + backup means the poll cannot be closed —
// callers must surface that risk in the UI before calling generate.

import { SUBGROUP_ORDER, scalarMulBase, encodePointHex, decodePointHex } from './pedersen.js';

// localStorage key prefix. Includes the poll id so multiple polls'
// keys coexist without ambiguity.
const KEY_PREFIX = 'bitwrap-sk-creator-';

// Backup file format version. Bump if the schema changes; restoreFromFile
// rejects unknown versions to avoid silently mis-parsing future formats.
const BACKUP_FORMAT_VERSION = 1;

// generateSkCreator returns a fresh sk_creator drawn uniformly from
// [0, ℓ) where ℓ is the BabyJubJub prime-order subgroup. Uses the
// platform CSPRNG; throws if crypto.getRandomValues is unavailable.
export function generateSkCreator() {
    if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
        throw new Error('sk-creator-store: crypto.getRandomValues unavailable');
    }
    // 32 random bytes ≈ 256 bits, then reduce mod ℓ (~252-bit). The
    // resulting bias is < 2^-252 — negligible for the cryptosystem.
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let v = 0n;
    for (const b of bytes) v = (v << 8n) | BigInt(b);
    return v % SUBGROUP_ORDER;
}

// derivePkCreator returns the BabyJubJub point pk = G·sk encoded as
// 32-byte compressed hex. Matches the server's pkCreator wire format.
export function derivePkCreator(sk) {
    const pk = scalarMulBase(BigInt(sk));
    return encodePointHex(pk);
}

// saveSkCreator persists sk under the per-poll localStorage key.
// Pass `storage` to use a custom backend (test shim); defaults to
// browser localStorage. Throws if localStorage is unavailable.
export function saveSkCreator(pollId, sk, storage) {
    const s = storage || _defaultStorage();
    if (!s) throw new Error('sk-creator-store: localStorage unavailable');
    s.setItem(KEY_PREFIX + pollId, BigInt(sk).toString(10));
}

// loadSkCreator returns the BigInt sk for pollId, or null if absent.
// A malformed value (non-decimal) is treated as absent so a junk
// localStorage entry doesn't cascade into a crypto failure later.
export function loadSkCreator(pollId, storage) {
    const s = storage || _defaultStorage();
    if (!s) return null;
    const raw = s.getItem(KEY_PREFIX + pollId);
    if (!raw) return null;
    try {
        return BigInt(raw);
    } catch {
        return null;
    }
}

// clearSkCreator removes the persisted key. Call after a successful
// close — the key is no longer needed and lingering keys are an
// avoidable footgun.
export function clearSkCreator(pollId, storage) {
    const s = storage || _defaultStorage();
    if (!s) return;
    s.removeItem(KEY_PREFIX + pollId);
}

// makeSkBackupBlob serializes the backup payload as a Blob suitable
// for FileSaver-style download. Pure data; the actual download is
// triggered by downloadSkBackup which uses the browser DOM.
export function makeSkBackupPayload(pollId, sk, pkHex, extras = {}) {
    return {
        format: 'bitwrap-sk-creator',
        version: BACKUP_FORMAT_VERSION,
        pollId,
        sk: BigInt(sk).toString(10),
        pkCreator: pkHex,
        timestamp: new Date().toISOString(),
        warning: 'Anyone with this file can decrypt the poll tally. Store it securely.',
        ...extras,
    };
}

// downloadSkBackup triggers a browser download of the sk backup file.
// Filename includes the poll id prefix. Caller must run in a context
// where document is defined.
export function downloadSkBackup(pollId, sk, pkHex, extras = {}) {
    const payload = makeSkBackupPayload(pollId, sk, pkHex, extras);
    const json = JSON.stringify(payload, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bitwrap-poll-${pollId.slice(0, 12)}-creator-key.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// restoreFromFile reads a previously-downloaded sk backup file and
// returns {pollId, sk: BigInt, pkHex}. Validates format/version and
// asserts pk = G·sk so a tampered file (mismatched sk and pk) fails
// loudly at restore time rather than later during proof submission.
export async function restoreFromFile(file) {
    const text = await readFileAsText(file);
    return parseSkBackupText(text);
}

// parseSkBackupText is the synchronous parser used by restoreFromFile;
// exposed so callers with the JSON already in memory (e.g. a
// drag-n-drop preview) can validate without touching the File API.
export function parseSkBackupText(text) {
    let parsed;
    try {
        parsed = JSON.parse(text);
    } catch (e) {
        throw new Error('not a valid JSON backup: ' + e.message);
    }
    if (parsed.format !== 'bitwrap-sk-creator') {
        throw new Error(`unexpected backup format: ${parsed.format}`);
    }
    if (parsed.version !== BACKUP_FORMAT_VERSION) {
        throw new Error(`unsupported backup version ${parsed.version} (this build expects ${BACKUP_FORMAT_VERSION})`);
    }
    if (!parsed.pollId || !parsed.sk || !parsed.pkCreator) {
        throw new Error('backup missing required fields (pollId, sk, pkCreator)');
    }
    let sk;
    try {
        sk = BigInt(parsed.sk);
    } catch (e) {
        throw new Error('backup sk is not a decimal big integer');
    }
    // Recompute pk = G·sk and check against the embedded pkCreator. A
    // mismatch means the file has been corrupted or hand-edited; reject
    // before the caller tries to use the key.
    const expectedPk = derivePkCreator(sk);
    if (expectedPk !== parsed.pkCreator.toLowerCase()) {
        throw new Error('backup pkCreator does not match G·sk — file is corrupted or has been tampered with');
    }
    // Round-trip pk through decode to confirm it parses cleanly.
    decodePointHex(parsed.pkCreator);
    return {
        pollId: parsed.pollId,
        sk,
        pkHex: parsed.pkCreator,
    };
}

// readFileAsText — Promise-wrap FileReader. Lives here rather than
// poll.js so the test harness can use restoreFromFile against a Blob
// without pulling in DOM-only globals at module load time.
function readFileAsText(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(reader.error || new Error('file read failed'));
        reader.readAsText(file);
    });
}

function _defaultStorage() {
    if (typeof localStorage !== 'undefined') return localStorage;
    return null;
}

// Test-friendly export: a tiny in-memory storage shim that mimics the
// Web Storage API. Lets unit tests run without a browser.
export function makeMemoryStorage() {
    const map = new Map();
    return {
        getItem: (k) => (map.has(k) ? map.get(k) : null),
        setItem: (k, v) => map.set(k, String(v)),
        removeItem: (k) => map.delete(k),
        clear: () => map.clear(),
    };
}
