// Playwright fixture: injects a real-signing window.ethereum mock into pages.
// Uses the same secp256k1 implementation as public/dev-wallet.js but runs
// entirely in-browser — no server calls for signing.
//
// Tests get a deterministic wallet with a known private key. Signatures are
// real EIP-191 personal_sign that the backend's VerifySignature can recover.

import { test as base } from '@playwright/test';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Read the dev-wallet.js source — it contains all the secp256k1 primitives
// we need (pointMul, keccak256, signMessage, getAddress, etc.)
const devWalletSrc = readFileSync(
  join(__dirname, '..', 'public', 'dev-wallet.js'), 'utf-8'
);

// Strip the ES module parts (export, import) to get a plain script
const cryptoFunctions = devWalletSrc
  .replace(/^export\s+/gm, '')
  .replace(/^import\s+.*$/gm, '');

// Hardcoded test private key (from Hardhat/Anvil account 0 — never used for real funds)
const TEST_PRIVATE_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

const walletInitScript = `
${cryptoFunctions}

// Inject window.ethereum with real signing
(function() {
  const PRIV_KEY = BigInt('${TEST_PRIVATE_KEY}');
  const ADDRESS = getAddress(PRIV_KEY);

  window.ethereum = {
    isMetaMask: true,
    isTestWallet: true,
    selectedAddress: ADDRESS,

    async request({ method, params }) {
      switch (method) {
        case 'eth_requestAccounts':
        case 'eth_accounts':
          return [ADDRESS];

        case 'personal_sign': {
          const [message] = params;
          const sig = signMessage(message, PRIV_KEY);
          return sig;
        }

        case 'eth_chainId':
          return '0x1';

        case 'net_version':
          return '1';

        default:
          throw new Error('test-wallet: unsupported method ' + method);
      }
    },

    on() {},
    removeListener() {},
  };

  // Also announce via EIP-6963 so the app picks it up
  window.dispatchEvent(new CustomEvent('eip6963:announceProvider', {
    detail: {
      info: { uuid: 'test-wallet', name: 'Test Wallet', icon: '', rdns: 'io.bitwrap.test' },
      provider: window.ethereum,
    }
  }));
})();
`;

export const test = base.extend({
  context: async ({ context }, use) => {
    await context.addInitScript({ content: walletInitScript });
    await use(context);
  },
  walletAddress: async ({}, use) => {
    // Anvil account 0 — the test key in the injected script
    await use('0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266');
  },
});
