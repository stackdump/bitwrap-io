// @ts-check
import { defineConfig } from '@playwright/test';
import 'dotenv/config';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8088';

export default defineConfig({
  testDir: '.',
  timeout: 60000,
  use: {
    baseURL: BASE_URL,
  },
  projects: [
    // Fast path: dev-wallet shim + API smoke tests. CI runs this on every PR.
    {
      name: 'chromium',
      testMatch: ['bitwrap.spec.js', 'poll-e2e.spec.js'],
      use: { browserName: 'chromium', headless: true },
    },
    // Real-signing wallet tests via e2e/wallet-fixture.js. The fixture
    // injects window.ethereum with a deterministic secp256k1 keypair —
    // no browser extension needed, so headless works in CI.
    {
      name: 'wallet',
      testMatch: 'real-wallet.spec.js',
      use: { browserName: 'chromium', headless: true },
      timeout: 120000,
    },
  ],
});
