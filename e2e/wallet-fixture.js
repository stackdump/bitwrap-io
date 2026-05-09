// Playwright fixture: injects a real-signing window.ethereum mock into pages.
// Uses the same secp256k1 implementation as public/dev-wallet.js but runs
// entirely in-browser — no server calls for signing.
//
// Default key is Anvil account 0 (deterministic, suits local CI). Override
// with `test.use({ walletPrivateKey: '0x...' })` — useful for prod tests
// where the per-wallet rate limiter would otherwise stomp on parallel runs.

import { test as base } from '@playwright/test';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { randomBytes } from 'crypto';

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

// Anvil account 0 — well-known test key. Default for local CI.
const ANVIL_ACCOUNT_0 = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

function buildInitScript(privKeyHex) {
  return `
${cryptoFunctions}

(function() {
  const PRIV_KEY = BigInt('${privKeyHex}');
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

  window.dispatchEvent(new CustomEvent('eip6963:announceProvider', {
    detail: {
      info: { uuid: 'test-wallet', name: 'Test Wallet', icon: '', rdns: 'io.bitwrap.test' },
      provider: window.ethereum,
    }
  }));
})();
`;
}

// Generate a fresh secp256k1 private key. Use this in prod tests so each
// run gets its own wallet identity and doesn't pile up against the
// per-wallet rate limiter (5 polls / hour).
export function freshPrivateKey() {
  return '0x' + randomBytes(32).toString('hex');
}

// Build a node-side signer using the same crypto as the page-injected
// wallet. Lets API-only tests sign without spinning up a browser.
export function nodeWallet(privKeyHex = freshPrivateKey()) {
  const ctx = {};
  new Function('ctx',
    cryptoFunctions + '\nctx.signMessage = signMessage; ctx.getAddress = getAddress;'
  )(ctx);
  const priv = BigInt(privKeyHex);
  return {
    privateKey: privKeyHex,
    address: ctx.getAddress(priv),
    sign: (msg) => ctx.signMessage(msg, priv),
  };
}

export const test = base.extend({
  // Override per-file or per-test via test.use({ walletPrivateKey: '0x...' }).
  walletPrivateKey: [ANVIL_ACCOUNT_0, { option: true }],

  context: async ({ context, walletPrivateKey }, use) => {
    await context.addInitScript({ content: buildInitScript(walletPrivateKey) });
    await use(context);
  },

  walletAddress: async ({ walletPrivateKey }, use) => {
    await use(nodeWallet(walletPrivateKey).address);
  },
});
