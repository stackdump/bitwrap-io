// @ts-check
// Prod-targeted e2e — runs against any bitwrap deployment with no -dev flag.
// Default target is https://bitwrap.io (override via BASE_URL).
//
// Constraints we work around:
//   - No /api/dev/sign on prod. We sign with nodeWallet() (same crypto as
//     the in-browser dev-wallet) instead.
//   - Per-IP rate limiter caps poll creation at 5/hour. We create exactly
//     one poll for the wallet flow, with a fresh key per run, and tag the
//     title so noise on prod is identifiable.
//   - Per-wallet rate limiter is sidestepped by freshPrivateKey().
//
// Run: cd e2e && npx playwright test --project=prod

import { test as base, expect } from '@playwright/test';
import { nodeWallet, freshPrivateKey } from './wallet-fixture.js';

const test = base; // page tests here don't need the wallet fixture

test.describe.configure({ mode: 'serial' });

test.describe('prod | static pages', () => {
  test('landing renders', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveTitle(/bitwrap/i);
    await expect(page.locator('.nav-links').getByText('Editor')).toBeVisible();
    await expect(page.locator('.nav-links').getByText('Polls')).toBeVisible();
  });

  test('editor loads', async ({ page }) => {
    await page.goto('/editor');
    await expect(page.locator('petri-view')).toBeAttached();
    await expect(page.locator('#btn-save')).toBeVisible();
  });

  test('poll page loads', async ({ page }) => {
    await page.goto('/poll');
    await expect(page.locator('#poll-list')).toBeAttached();
  });

  test('dev-wallet.js is served (current build, no /api/dev/sign delegation)', async ({ request }) => {
    const resp = await request.get('/dev-wallet.js');
    expect(resp.ok()).toBeTruthy();
    const src = await resp.text();
    // Sanity: the client-side signing path is the live one
    expect(src).toContain('signMessage(msgInput, privKey)');
    expect(src).not.toContain("fetch('/api/dev/sign'");
  });
});

test.describe('prod | API surface', () => {
  test('GET /api/templates returns 6 templates', async ({ request }) => {
    const resp = await request.get('/api/templates');
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    const ids = data.templates.map(t => t.id).sort();
    expect(ids).toEqual(['erc1155', 'erc20', 'erc4626', 'erc5725', 'erc721', 'vote']);
  });

  test('GET /api/circuits lists compiled circuits', async ({ request }) => {
    const resp = await request.get('/api/circuits');
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    const names = data.circuits.map(c => c.name);
    for (const n of ['transfer', 'mint', 'burn', 'approve', 'voteCast', 'tallyProof']) {
      expect(names).toContain(n);
    }
    for (const c of data.circuits) expect(c.status).toBe('compiled');
  });

  test('GET /api/vk/transfer returns binary verifying key', async ({ request }) => {
    const resp = await request.get('/api/vk/transfer');
    expect(resp.ok()).toBeTruthy();
    const body = await resp.body();
    expect(body.length).toBeGreaterThan(0);
  });

  test('GET /api/vk/transfer/solidity returns Solidity verifier', async ({ request }) => {
    const resp = await request.get('/api/vk/transfer/solidity');
    expect(resp.ok()).toBeTruthy();
    const text = await resp.text();
    expect(text).toContain('pragma solidity');
    expect(text).toMatch(/contract\s+\w*Verifier/);
  });

  test('POST /api/solgen erc20 generates valid Solidity', async ({ request }) => {
    const resp = await request.post('/api/solgen', { data: { template: 'erc20' } });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.solidity).toContain('pragma solidity');
    expect(data.solidity).toContain('contract ERC20');
    expect(data.filename).toMatch(/\.sol$/);
  });

  test('POST /api/testgen erc20 generates Foundry tests', async ({ request }) => {
    const resp = await request.post('/api/testgen', { data: { template: 'erc20' } });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.solidity).toContain('forge-std/Test.sol');
    expect(data.filename).toMatch(/\.t\.sol$/);
  });

  test('POST /api/genesisgen erc20 generates deploy script', async ({ request }) => {
    const resp = await request.post('/api/genesisgen', { data: { template: 'erc20' } });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.solidity).toContain('forge-std/Script.sol');
    expect(data.filename).toMatch(/\.s\.sol$/);
  });

  test('GET /api/bundle/erc20 returns ZIP', async ({ request }) => {
    const resp = await request.get('/api/bundle/erc20');
    expect(resp.ok()).toBeTruthy();
    expect(resp.headers()['content-type']).toBe('application/zip');
    const body = await resp.body();
    expect(body[0]).toBe(0x50); // 'P'
    expect(body[1]).toBe(0x4b); // 'K'
  });

  test('POST /api/compile compiles a real .btw schema', async ({ request }) => {
    const btw = `schema Counter {
  version "1.0.0"
  register COUNT uint256 observable
  fn(increment) {
    var amount amount
    increment -|amount|> COUNT
  }
}`;
    const resp = await request.post('/api/compile', {
      headers: { 'Content-Type': 'text/plain' },
      data: btw,
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.name).toBe('Counter');
    expect(data.actions.map(a => a.id)).toContain('increment');
  });

  test('POST /api/save round-trip → /o/{cid} → /img/{cid}.svg', async ({ request }) => {
    const erc20 = await (await request.get('/api/templates/erc20')).json();
    const save = await request.post('/api/save', { data: erc20 });
    expect(save.ok()).toBeTruthy();
    const { cid } = await save.json();
    expect(cid).toMatch(/^z[A-Za-z0-9]+$/);

    const obj = await request.get(`/o/${cid}`);
    expect(obj.ok()).toBeTruthy();

    const svg = await request.get(`/img/${cid}.svg`);
    expect(svg.ok()).toBeTruthy();
    const svgText = await svg.text();
    expect(svgText).toContain('<svg');
  });

  test('POST /api/prove rejects invalid witness with constraint failure', async ({ request }) => {
    const resp = await request.post('/api/prove', {
      data: {
        circuit: 'approve',
        witness: {
          preStateRoot: '0', postStateRoot: '0',
          caller: '42', spender: '99', amount: '500',
          owner: '99', // owner != caller — circuit rejects at constraint #0
        },
      },
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.circuit).toBe('approve');
    expect(data.error).toContain('constraint');
  });

  test('POST /api/prove rejects unknown circuit with helpful list', async ({ request }) => {
    const resp = await request.post('/api/prove', {
      data: { circuit: 'nonexistent', witness: { x: '1' } },
    });
    expect(resp.status()).toBe(400);
    const text = await resp.text();
    expect(text).toContain('Unknown circuit');
    expect(text).toContain('approve');
  });
});

test.describe('prod | wallet flow (fresh key, burns 1 IP rate-limit slot)', () => {
  test('create poll → register voters → sign registry root', async ({ request }) => {
    const wallet = nodeWallet(freshPrivateKey());
    const title = 'playwright-prod ' + new Date().toISOString();

    // create
    const createSig = wallet.sign('bitwrap-create-poll:' + title);
    const created = await request.post('/api/polls', {
      data: {
        title,
        description: 'e2e test — auto-cleaned by 60min expiry',
        choices: ['yes', 'no', 'abstain'],
        durationMinutes: 60,
        voterCommitments: [],
        registryRoot: '',
        creator: wallet.address,
        signature: createSig,
      },
    });
    if (created.status() === 429) {
      test.skip(true, 'IP rate-limited (5 polls/hr) — retry later');
    }
    expect(created.ok()).toBeTruthy();
    const { id: pollId } = await created.json();
    expect(pollId).toMatch(/^[0-9a-f]{32}$/);

    // register 3 voters (no sig required)
    for (let i = 1; i <= 3; i++) {
      const commitment = '0x' + i.toString(16).padStart(64, '0');
      const reg = await request.post(`/api/polls/${pollId}/register`, {
        data: { commitment },
      });
      expect(reg.ok()).toBeTruthy();
      const data = await reg.json();
      expect(data.count).toBe(i);
    }

    // sign-registry-root
    const registry = await (await request.get(`/api/polls/${pollId}/registry`)).json();
    expect(registry.count).toBe(3);
    const rrMsg = `bitwrap-registry-root:${pollId}:${registry.root}:${registry.count}`;
    const rrSig = wallet.sign(rrMsg);
    const signed = await request.post(`/api/polls/${pollId}/sign-registry-root`, {
      data: { signature: rrSig },
    });
    expect(signed.ok()).toBeTruthy();
    const sd = await signed.json();
    expect(sd.status).toBe('signed');

    // verify state landed
    const final = await (await request.get(`/api/polls/${pollId}`)).json();
    const poll = final.poll || final;
    expect(poll.status).toBe('active');
    expect(poll.creator.toLowerCase()).toBe(wallet.address.toLowerCase());
    expect(poll.voterCommitments).toHaveLength(3);
    expect(poll.registryRootSigs).toHaveLength(1);
  });

  test('wrong-account signature is rejected (403)', async ({ request }) => {
    const a = nodeWallet(freshPrivateKey());
    const b = nodeWallet(freshPrivateKey()); // different identity
    const title = 'playwright-prod-mismatch ' + new Date().toISOString();

    // sign with a, claim creator = b
    const sig = a.sign('bitwrap-create-poll:' + title);
    const resp = await request.post('/api/polls', {
      data: {
        title,
        description: 'should-fail',
        choices: ['yes', 'no'],
        durationMinutes: 60,
        voterCommitments: [],
        registryRoot: '',
        creator: b.address, // <-- wrong
        signature: sig,
      },
    });
    expect(resp.status()).toBe(403);
  });
});
