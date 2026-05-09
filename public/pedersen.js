// Pedersen / ElGamal primitives for the homomorphic tally protocol
// (Phase B / vote schema v3).
//
// Mirror of prover/pedersen.go. Pure BigInt — zero deps. Curve is
// BabyJubJub (twisted Edwards over BN254's scalar field Fr), the
// embedded curve used by gnark for in-circuit ECC over BN254 Groth16.
//
// Curve equation: a·x² + y² = 1 + d·x²·y² over Fr, with a = -1
// (gnark-crypto / iden3 reduced-parameter form).
//
// Encoding: 32-byte compressed (gnark-crypto / RFC 8032) — little-
// endian Y with the sign of X stored in the MSB of byte 31.
//
// H is the deterministic independent generator. The Go side derives
// it via try-and-increment (SHA-256 + cofactor-clearing); JS does not
// re-derive — it loads H as a fixed constant from pedersen_vectors.json
// and the parity test asserts byte-equality. H is a public parameter,
// so agreement on bytes is what matters, not algorithm portability.

// ---- Field & curve constants -----------------------------------------------

// BN254 scalar field — also the BabyJubJub coordinate field.
export const Fr = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Twisted-Edwards parameters (a, d) reduced into Fr.
const A = Fr - 1n;                    // a = -1 mod Fr
const D = 12181644023421730124874158521699555681764249180949974110617291017600649128846n;

// Prime-order subgroup order ℓ; cofactor = 8.
export const SUBGROUP_ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
export const COFACTOR = 8n;

// Canonical BabyJubJub base point (gnark-crypto / iden3 standard).
export const G = Object.freeze({
    x: 9671717474070082183213120605117400219616337014328744928644933853176787189663n,
    y: 16950150798460657717958625567821834550301663161624707787222815936182638968203n,
});

// Identity element (twisted Edwards): (0, 1).
export const ZERO = Object.freeze({ x: 0n, y: 1n });

const FR_HALF = (Fr - 1n) / 2n;
const FR_INV_EXP = Fr - 2n;          // by Fermat's little theorem

// Tonelli-Shanks parameters for sqrt mod Fr. BN254's Fr has 2-adicity
// 28, so simple p≡3 (mod 4) shortcut doesn't apply.
//   Fr − 1 = q · 2^s  with s = 28 and q odd
//   z      = 5  (a known quadratic non-residue mod Fr)
const TS_S = 28n;
const TS_Q = (Fr - 1n) >> TS_S;
const TS_Z = 5n;

// Compression flag bits (top bit of the *last* byte after little-endian
// serialization).
const FLAG_X_NEG = 0x80;
const FLAG_MASK  = 0x7f;

// ---- Field arithmetic ------------------------------------------------------

const mod = (a, m = Fr) => {
    const r = a % m;
    return r < 0n ? r + m : r;
};

function modPow(base, exp, m = Fr) {
    let r = 1n, b = mod(base, m), e = exp;
    while (e > 0n) {
        if (e & 1n) r = (r * b) % m;
        b = (b * b) % m;
        e >>= 1n;
    }
    return r;
}

const modInv = (a) => modPow(a, FR_INV_EXP);

// Tonelli-Shanks square-root mod Fr; returns null on non-residue.
function sqrtFr(n) {
    if (n === 0n) return 0n;
    // Euler's criterion: n^((Fr-1)/2) must be 1 for QR.
    if (modPow(n, FR_HALF) !== 1n) return null;

    let M = TS_S;
    let c = modPow(TS_Z, TS_Q);
    let t = modPow(n, TS_Q);
    let R = modPow(n, (TS_Q + 1n) >> 1n);
    while (true) {
        if (t === 1n) return R;
        let i = 0n;
        let temp = t;
        while (temp !== 1n) {
            temp = (temp * temp) % Fr;
            i += 1n;
            if (i === M) return null; // shouldn't happen if Euler passed
        }
        const b = modPow(c, 1n << (M - i - 1n));
        M = i;
        c = (b * b) % Fr;
        t = (t * c) % Fr;
        R = (R * b) % Fr;
    }
}

// fr_LexicographicallyLargest mirrors gnark's predicate: x is "negative"
// iff x > (Fr-1)/2.
const isLargest = (x) => x > FR_HALF;

// ---- Curve arithmetic (twisted-Edwards, unified addition) ------------------

export function isOnCurve(P) {
    if (!P) return false;
    const x2 = (P.x * P.x) % Fr;
    const y2 = (P.y * P.y) % Fr;
    const lhs = mod(A * x2 + y2);
    const rhs = mod(1n + D * x2 % Fr * y2);
    return lhs === rhs;
}

export const pointEq = (P, Q) => P.x === Q.x && P.y === Q.y;

export function pointNeg(P) {
    return { x: mod(-P.x), y: P.y };
}

// Unified twisted-Edwards addition (works for doubling too):
//   x3 = (x1·y2 + y1·x2) / (1 + d·x1·x2·y1·y2)
//   y3 = (y1·y2 − a·x1·x2) / (1 − d·x1·x2·y1·y2)
export function pointAdd(P, Q) {
    const x1y2 = P.x * Q.y % Fr;
    const y1x2 = P.y * Q.x % Fr;
    const y1y2 = P.y * Q.y % Fr;
    const x1x2 = P.x * Q.x % Fr;
    const dx1x2y1y2 = D * x1x2 % Fr * y1y2 % Fr;
    const denX = mod(1n + dx1x2y1y2);
    const denY = mod(1n - dx1x2y1y2);
    const x3 = mod((x1y2 + y1x2) * modInv(denX));
    const y3 = mod((y1y2 - A * x1x2) * modInv(denY));
    return { x: x3, y: y3 };
}

export const pointDouble = (P) => pointAdd(P, P);

export function scalarMul(k, P) {
    let n = mod(k, SUBGROUP_ORDER);
    if (n === 0n) return ZERO;
    let R = ZERO;
    let A_ = P;
    while (n > 0n) {
        if (n & 1n) R = pointAdd(R, A_);
        A_ = pointAdd(A_, A_);
        n >>= 1n;
    }
    return R;
}

export const scalarMulBase = (k) => scalarMul(k, G);

export function isInPrimeSubgroup(P) {
    return pointEq(scalarMul(SUBGROUP_ORDER, P), ZERO);
}

// ---- Encoding --------------------------------------------------------------

function bigintToLEBytes(x, len) {
    let v = x;
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        out[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    if (v !== 0n) throw new Error(`bigint too large for ${len} LE bytes`);
    return out;
}

function leBytesToBigint(buf) {
    let v = 0n;
    for (let i = buf.length - 1; i >= 0; i--) {
        v = (v << 8n) | BigInt(buf[i]);
    }
    return v;
}

export function encodePoint(P) {
    const out = bigintToLEBytes(P.y, 32);
    if (isLargest(P.x)) out[31] |= FLAG_X_NEG;
    return out;
}

export function decodePoint(buf) {
    if (buf.length !== 32) throw new Error(`expected 32 bytes, got ${buf.length}`);
    const xNeg = (buf[31] & FLAG_X_NEG) !== 0;
    const yBuf = new Uint8Array(buf);
    yBuf[31] &= FLAG_MASK;
    const y = leBytesToBigint(yBuf);
    if (y >= Fr) throw new Error('y out of field');
    // x² = (y² − 1) / (d·y² − a)
    const ySq = y * y % Fr;
    const num = mod(ySq - 1n);
    const den = mod(D * ySq - A);
    if (den === 0n) throw new Error('decode: degenerate denominator');
    const xSq = mod(num * modInv(den));
    let x = sqrtFr(xSq);
    if (x === null) throw new Error('point not on curve (no sqrt)');
    if (isLargest(x) !== xNeg) x = mod(-x);
    const P = { x, y };
    if (!isOnCurve(P)) throw new Error('decoded point not on curve');
    return P;
}

export const encodePointHex = (P) =>
    Array.from(encodePoint(P), (b) => b.toString(16).padStart(2, '0')).join('');

export function decodePointHex(hex) {
    if (hex.length !== 64) throw new Error(`expected 64 hex chars, got ${hex.length}`);
    const buf = new Uint8Array(32);
    for (let i = 0; i < 32; i++) buf[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return decodePoint(buf);
}

// ---- ElGamal ---------------------------------------------------------------

export function encrypt(v, r, pk) {
    const vRed = mod(v, SUBGROUP_ORDER);
    const rRed = mod(r, SUBGROUP_ORDER);
    const A_ = scalarMulBase(rRed);
    const gv = scalarMulBase(vRed);
    const pkr = scalarMul(rRed, pk);
    const B_ = pointAdd(gv, pkr);
    return { A: A_, B: B_ };
}

export function aggregate(cts) {
    let A_ = ZERO, B_ = ZERO;
    for (const ct of cts) {
        A_ = pointAdd(A_, ct.A);
        B_ = pointAdd(B_, ct.B);
    }
    return { A: A_, B: B_ };
}

export class TallyExceedsRange extends Error {
    constructor() { super('pedersen: tally exceeds maxTally range'); }
}

export function decrypt(ct, sk, maxTally) {
    if (maxTally < 0) throw new Error('maxTally must be non-negative');
    const skA = scalarMul(sk, ct.A);
    const M = pointAdd(ct.B, pointNeg(skA));
    if (pointEq(M, ZERO)) return 0;
    let probe = ZERO;
    for (let t = 1; t <= maxTally; t++) {
        probe = pointAdd(probe, G);
        if (pointEq(probe, M)) return t;
    }
    throw new TallyExceedsRange();
}

// ---- H constant ------------------------------------------------------------
//
// Loaded from pedersen_vectors.json. Recompute on the Go side via
//   go test ./prover -run TestPedersenH -v

let H_CACHED = null;

export function setPedersenH(hex) {
    H_CACHED = decodePointHex(hex);
}

export function getPedersenH() {
    if (H_CACHED === null) {
        throw new Error('pedersen.js: H is not initialized — call setPedersenH(hex) first');
    }
    return H_CACHED;
}
