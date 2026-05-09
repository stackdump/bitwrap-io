// @ts-check
import { defineConfig } from '@playwright/test';
import 'dotenv/config';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8088';
const PROD_URL = process.env.PROD_URL || 'https://bitwrap.io';

export default defineConfig({
  testDir: '.',
  timeout: 60000,
  use: {
    baseURL: BASE_URL,
  },
  projects: [
    // Fast path: dev-wallet shim + API smoke tests. CI runs this on every PR.
    // Requires `./bitwrap -dev` (uses /api/dev/sign for setup helpers).
    {
      name: 'chromium',
      testMatch: ['bitwrap.spec.js', 'poll-e2e.spec.js'],
      use: { browserName: 'chromium', headless: true },
    },
    // Real-signing wallet tests via e2e/wallet-fixture.js. The fixture
    // injects window.ethereum with a deterministic secp256k1 keypair —
    // no browser extension needed, so headless works in CI.
    // Also requires `-dev` (uses /api/dev/sign for non-creator setup).
    {
      name: 'wallet',
      testMatch: 'real-wallet.spec.js',
      use: { browserName: 'chromium', headless: true },
      timeout: 120000,
    },
    // v3 (homomorphic-tally) lifecycle test. Same wallet fixture as
    // 'wallet' but with a much longer timeout — the in-browser WASM
    // prover compiles + runs Setup for voteCastHomomorphic_8 (~70k
    // constraints) and tallyDecrypt_8 (~40k) on first use, so a
    // single end-to-end run can take 90s+ even on fast hardware.
    // Requires the bitwrap server running with prover enabled (i.e.
    // `make run` or `./bitwrap -dev` — both default to prover-on).
    {
      name: 'v3',
      testMatch: ['v3.spec.js', 'v3_dump_witness.spec.js'],
      use: { browserName: 'chromium', headless: true },
      timeout: 300000,
      workers: 1,
      retries: 0,
    },
    // Prod-targeted suite — runs against any deployment with no -dev flag.
    // Default target: https://bitwrap.io (override with PROD_URL).
    // Single worker to avoid IP rate-limit collisions; one wallet test
    // burns 1 of 5 hourly poll-creation slots per IP.
    {
      name: 'prod',
      testMatch: 'prod.spec.js',
      use: { browserName: 'chromium', headless: true, baseURL: PROD_URL },
      timeout: 60000,
      workers: 1,
      retries: 0,
    },
  ],
});
