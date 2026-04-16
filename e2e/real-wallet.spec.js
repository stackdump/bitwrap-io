// @ts-check
// Real-wallet e2e — exercises the actual window.ethereum → personal_sign path
// using a page-injected wallet with real secp256k1 signing.
//
// Signatures are cryptographically valid EIP-191 personal_sign, identical to
// what MetaMask / Trust Wallet produce. The backend's VerifySignature recovers
// the same address — proving the full signing path works end-to-end.
//
// Run with: npx playwright test --project=wallet

import { test } from './wallet-fixture.js';

const { expect } = test;

test.describe('Real-wallet poll lifecycle (client-side signing)', () => {
  test('create poll — real secp256k1 signature verified by backend', async ({
    page, walletAddress, request,
  }) => {
    await page.goto('/poll#create');

    await page.locator('input[placeholder="What should we decide?"]').fill('Wallet test');
    await page.locator('input[placeholder="Option 1"]').fill('Yes');
    await page.locator('input[placeholder="Option 2"]').fill('No');

    const createResp = page.waitForResponse(r =>
      r.url().endsWith('/api/polls') && r.request().method() === 'POST');

    await page.getByRole('button', { name: 'Create Poll' }).click();

    const resp = await createResp;
    expect(resp.status()).toBe(200);
    const { id: pollId } = await resp.json();
    expect(pollId).toBeTruthy();

    // Verify the backend recovered the correct address from the signature
    const pollData = await (await request.get(`/api/polls/${pollId}`)).json();
    const poll = pollData.poll || pollData;
    expect(poll.status).toBe('active');
    expect(poll.creator.toLowerCase()).toBe(walletAddress);
  });

  test('register voter — wallet-signed commitment added to registry', async ({
    page, request,
  }) => {
    // Create a poll via dev-sign API
    const devSign = await request.post('/api/dev/sign', {
      data: { message: 'bitwrap-create-poll:Register test', account: 5 },
    });
    const { signature, address } = await devSign.json();
    const created = await request.post('/api/polls', {
      data: { title: 'Register test', choices: ['A', 'B'], duration: 3600, creator: address, signature },
    });
    const { id: pollId } = await created.json();

    // Pre-register one voter via API so the registry bar becomes visible
    await request.post(`/api/polls/${pollId}/register`, {
      data: { commitment: '0x' + '1'.padStart(64, '0') },
    });

    await page.goto(`/poll#${pollId}`);
    await page.waitForSelector('#registry-bar', { state: 'visible', timeout: 5000 });

    const before = await (await request.get(`/api/polls/${pollId}/registry`)).json();

    const regResp = page.waitForResponse(r =>
      r.url().includes(`/api/polls/${pollId}/register`) && r.request().method() === 'POST',
      { timeout: 15000 });

    await page.getByRole('button', { name: /Register to Vote/i }).click();
    const resp = await regResp;
    expect(resp.status()).toBe(200);

    const after = await (await request.get(`/api/polls/${pollId}/registry`)).json();
    expect(after.count).toBe(before.count + 1);
  });

  test('close poll — only creator can close, signature verified', async ({
    page, walletAddress, request,
  }) => {
    await page.goto('/poll#create');
    await page.locator('input[placeholder="What should we decide?"]').fill('Close test');
    await page.locator('input[placeholder="Option 1"]').fill('A');
    await page.locator('input[placeholder="Option 2"]').fill('B');

    const createResp = page.waitForResponse(r =>
      r.url().endsWith('/api/polls') && r.request().method() === 'POST');
    await page.getByRole('button', { name: 'Create Poll' }).click();
    const { id: pollId } = await (await createResp).json();

    // Non-creator (dev-sign account 3) attempts close → 403
    const badSign = await (await request.post('/api/dev/sign', {
      data: { message: `bitwrap-close-poll:${pollId}`, account: 3 },
    })).json();
    const badClose = await request.post(`/api/polls/${pollId}/close`, {
      data: { creator: badSign.address, signature: badSign.signature },
    });
    expect(badClose.status()).toBe(403);

    // Creator closes via browser — real signing
    await page.goto(`/poll#${pollId}`);
    await page.waitForSelector('#btn-close', { state: 'visible', timeout: 10000 });

    const closeResp = page.waitForResponse(r =>
      r.url().includes(`/api/polls/${pollId}/close`), { timeout: 15000 });
    await page.getByRole('button', { name: 'Close Poll' }).click();
    const resp = await closeResp;
    expect(resp.status()).toBe(200);

    const closed = await (await request.get(`/api/polls/${pollId}`)).json();
    expect((closed.poll || closed).status).toBe('closed');
    expect((closed.poll || closed).creator.toLowerCase()).toBe(walletAddress);
  });

  test('wrong-account signature is rejected by VerifySignature', async ({ request }) => {
    const sig = await (await request.post('/api/dev/sign', {
      data: { message: 'bitwrap-create-poll:Spoof', account: 0 },
    })).json();
    const other = await (await request.post('/api/dev/sign', {
      data: { message: 'unused', account: 1 },
    })).json();

    const resp = await request.post('/api/polls', {
      data: {
        title: 'Spoof',
        choices: ['A', 'B'],
        duration: 3600,
        creator: other.address,
        signature: sig.signature,
      },
    });
    expect(resp.status()).toBeGreaterThanOrEqual(400);
  });
});
