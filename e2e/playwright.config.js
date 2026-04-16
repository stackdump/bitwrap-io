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
    // Slow path: real MetaMask extension via Synpress. Run with `npm run test:wallet`.
    // Extensions require headed mode and a persistent context.
    {
      name: 'wallet',
      testMatch: 'real-wallet.spec.js',
      use: { browserName: 'chromium', headless: false },
      timeout: 120000,
    },
  ],
});
