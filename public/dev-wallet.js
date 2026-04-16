// Dev wallet — ephemeral secp256k1 keypair for testing without MetaMask.
// Enable by adding ?dev-wallet to the URL or setting localStorage.devWallet = true.
//
// Creates a deterministic keypair per browser session (stored in sessionStorage).
// Provides a window.ethereum shim supporting eth_requestAccounts and personal_sign.

const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

function mod(a, m) { return ((a % m) + m) % m; }

function modInverse(a, m) {
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, m);
}

function pointAdd(x1, y1, x2, y2) {
  if (x1 === 0n && y1 === 0n) return [x2, y2];
  if (x2 === 0n && y2 === 0n) return [x1, y1];
  if (x1 === x2 && y1 === y2) return pointDouble(x1, y1);
  if (x1 === x2) return [0n, 0n];
  const lam = mod((y2 - y1) * modInverse(x2 - x1, P), P);
  const x3 = mod(lam * lam - x1 - x2, P);
  const y3 = mod(lam * (x1 - x3) - y1, P);
  return [x3, y3];
}

function pointDouble(x, y) {
  if (x === 0n && y === 0n) return [0n, 0n];
  const lam = mod(3n * x * x * modInverse(2n * y, P), P);
  const x3 = mod(lam * lam - 2n * x, P);
  const y3 = mod(lam * (x - x3) - y, P);
  return [x3, y3];
}

function pointMul(x, y, k) {
  let [rx, ry] = [0n, 0n];
  let [px, py] = [x, y];
  let n = k;
  while (n > 0n) {
    if (n & 1n) [rx, ry] = pointAdd(rx, ry, px, py);
    [px, py] = pointDouble(px, py);
    n >>= 1n;
  }
  return [rx, ry];
}

function bigToBytes(n, len) {
  const hex = n.toString(16).padStart(len * 2, '0');
  return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}

function bytesToBig(bytes) {
  return BigInt('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
}

function bytesToHex(bytes) {
  return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Keccak-256 using SubtleCrypto is not available (no keccak in WebCrypto).
// Minimal keccak-256 implementation for Ethereum address derivation.
function keccak256(data) {
  // Keccak-256 constants
  const RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
  ];
  const ROTC = [
    1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44
  ];
  const PILN = [
    10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1
  ];

  function rotl64(x, n) {
    n = BigInt(n);
    return ((x << n) | (x >> (64n - n))) & 0xFFFFFFFFFFFFFFFFn;
  }

  function keccakF(state) {
    for (let round = 0; round < 24; round++) {
      // θ
      const C = new Array(5);
      for (let x = 0; x < 5; x++) C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20];
      for (let x = 0; x < 5; x++) {
        const D = C[(x+4)%5] ^ rotl64(C[(x+1)%5], 1);
        for (let y = 0; y < 25; y += 5) state[x+y] ^= D;
      }
      // ρ and π
      let t = state[1];
      for (let i = 0; i < 24; i++) {
        const j = PILN[i];
        const tmp = state[j];
        state[j] = rotl64(t, ROTC[i]);
        t = tmp;
      }
      // χ (mask ~x to 64 bits since JS BigInt ~ gives -(n+1))
      const mask = 0xFFFFFFFFFFFFFFFFn;
      for (let y = 0; y < 25; y += 5) {
        const t0=state[y], t1=state[y+1], t2=state[y+2], t3=state[y+3], t4=state[y+4];
        state[y]   = t0 ^ ((~t1 & mask) & t2);
        state[y+1] = t1 ^ ((~t2 & mask) & t3);
        state[y+2] = t2 ^ ((~t3 & mask) & t4);
        state[y+3] = t3 ^ ((~t4 & mask) & t0);
        state[y+4] = t4 ^ ((~t0 & mask) & t1);
      }
      // ι
      state[0] ^= RC[round];
    }
  }

  // Pad input (rate=136 bytes for keccak-256, domain=0x01)
  const rate = 136;
  const input = data instanceof Uint8Array ? data : new TextEncoder().encode(data);
  const pLen = rate - (input.length % rate);
  const padded = new Uint8Array(input.length + pLen);
  padded.set(input);
  padded[input.length] = 0x01;
  padded[padded.length - 1] |= 0x80;

  // Absorb
  const state = new Array(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let v = 0n;
      for (let j = 7; j >= 0; j--) v = (v << 8n) | BigInt(padded[offset + i*8 + j]);
      state[i] ^= v;
    }
    keccakF(state);
  }

  // Squeeze 32 bytes
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let v = state[i];
    for (let j = 0; j < 8; j++) {
      out[i*8+j] = Number(v & 0xFFn);
      v >>= 8n;
    }
  }
  return out;
}

function getAddress(privKey) {
  const [px, py] = pointMul(Gx, Gy, privKey);
  const pubBytes = new Uint8Array(64);
  pubBytes.set(bigToBytes(px, 32), 0);
  pubBytes.set(bigToBytes(py, 32), 32);
  const hash = keccak256(pubBytes);
  return bytesToHex(hash.slice(12));
}

function signMessage(message, privKey) {
  // EIP-191 personal_sign: prefix + keccak256
  const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${msgBytes.length}`);
  const full = new Uint8Array(prefix.length + msgBytes.length);
  full.set(prefix);
  full.set(msgBytes, prefix.length);
  const hash = keccak256(full);
  const z = bytesToBig(hash);

  // Deterministic k via RFC 6979 (simplified: HMAC-like hash chain)
  const kInput = new Uint8Array(96);
  kInput.set(bigToBytes(privKey, 32), 0);
  kInput.set(hash, 32);
  kInput.set(bigToBytes(1n, 32), 64); // nonce
  let k = bytesToBig(keccak256(kInput));
  k = mod(k, N - 1n) + 1n;

  const [rx, ry] = pointMul(Gx, Gy, k);
  const r = mod(rx, N);
  if (r === 0n) throw new Error('bad k: r=0');

  let s = mod(modInverse(k, N) * mod(z + r * privKey, N), N);
  if (s === 0n) throw new Error('bad k: s=0');

  // Determine recovery id (v) BEFORE normalizing s
  let v = (ry % 2n === 0n) ? 27 : 28;

  // Ensure low-s (EIP-2)
  if (s > N / 2n) {
    s = N - s;
    v = (v === 27) ? 28 : 27;  // flip v when negating s
  }

  const sig = new Uint8Array(65);
  sig.set(bigToBytes(r, 32), 0);
  sig.set(bigToBytes(s, 32), 32);
  sig[64] = v;
  return bytesToHex(sig);
}

// ============ Dev Wallet Shim ============

function getOrCreateKey() {
  let hex = sessionStorage.getItem('devWalletKey');
  if (!hex) {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    sessionStorage.setItem('devWalletKey', hex);
  }
  return BigInt('0x' + hex);
}

export function isDevWalletEnabled() {
  return new URLSearchParams(location.search).has('dev-wallet') ||
         localStorage.getItem('devWallet') === 'true';
}

export function enableDevWallet() {
  if (!isDevWalletEnabled()) return;

  // Address will be set by first /api/dev/sign call; use placeholder initially
  let address = '0x0000000000000000000000000000000000000000';

  // Try to get address eagerly
  fetch('/api/dev/sign', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: 'init' })
  }).then(r => r.json()).then(data => {
    address = data.address;
    if (window.ethereum) window.ethereum.selectedAddress = address;
    console.log(`[dev-wallet] address: ${address}`);
    if (banner) banner.textContent = `Dev Wallet: ${address}`;
  }).catch(() => {});

  let banner = null;
  console.log('[dev-wallet] enabled');

  // Show banner
  banner = document.createElement('div');
  banner.style.cssText = 'position:fixed;bottom:0;left:0;right:0;background:#1a1a2e;color:#0f0;padding:6px 12px;font:12px monospace;z-index:9999;text-align:center;border-top:1px solid #333';
  banner.textContent = 'Dev Wallet: connecting...';
  document.body.appendChild(banner);

  // Shim window.ethereum
  window.ethereum = {
    isMetaMask: false,
    isDevWallet: true,
    selectedAddress: address,

    async request({ method, params }) {
      switch (method) {
        case 'eth_requestAccounts':
        case 'eth_accounts':
          return [address];

        case 'personal_sign': {
          const [message] = params;
          // Sign via server-side dev endpoint (avoids JS ECDSA complexity)
          const resp = await fetch('/api/dev/sign', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
          });
          if (!resp.ok) {
            const text = await resp.text();
            throw new Error(`dev-wallet sign failed: ${text}`);
          }
          const data = await resp.json();
          // Use the server-derived address (authoritative)
          address = data.address;
          console.log(`[dev-wallet] signed: ${message.slice(0, 50)}...`);
          return data.signature;
        }

        default:
          throw new Error(`dev-wallet: unsupported method ${method}`);
      }
    }
  };
}
