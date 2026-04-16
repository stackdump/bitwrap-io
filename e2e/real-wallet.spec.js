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

  test('vote with empty registry is rejected (must register first)', async ({ request }) => {
    // Create a poll via dev-sign API — registry starts empty
    const devSign = await request.post('/api/dev/sign', {
      data: { message: 'bitwrap-create-poll:Empty reg test', account: 8 },
    });
    const { signature, address } = await devSign.json();
    const created = await request.post('/api/polls', {
      data: { title: 'Empty reg test', choices: ['A', 'B'], duration: 3600, creator: address, signature },
    });
    const { id: pollId } = await created.json();

    // Attempt to vote without registering — should be rejected
    const voteResp = await request.post(`/api/polls/${pollId}/vote`, {
      data: {
        nullifier: '0x' + 'a'.padStart(64, '0'),
        voteCommitment: '0x' + 'b'.padStart(64, '0'),
        proof: 'dummy',
      },
    });
    expect(voteResp.status()).toBe(400);
    const text = await voteResp.text();
    expect(text).toContain('register before voting');
  });

  test('register then vote — full happy path', async ({ request }) => {
    const devSign = await request.post('/api/dev/sign', {
      data: { message: 'bitwrap-create-poll:Full flow', account: 9 },
    });
    const { signature, address } = await devSign.json();
    const created = await request.post('/api/polls', {
      data: { title: 'Full flow', choices: ['Yes', 'No'], duration: 3600, creator: address, signature },
    });
    const { id: pollId } = await created.json();

    // Register a commitment — this sets poll.RegistryRoot, unblocking votes
    const regResp = await request.post(`/api/polls/${pollId}/register`, {
      data: { commitment: '0x' + '7'.padStart(64, '0') },
    });
    expect(regResp.status()).toBe(200);

    // With registry non-empty and no prover enabled in test mode, a dummy
    // vote should be accepted (the ZK path is bypassed when proverSvc is nil).
    const voteResp = await request.post(`/api/polls/${pollId}/vote`, {
      data: {
        nullifier: '0x' + 'c'.padStart(64, '0'),
        voteCommitment: '0x' + 'd'.padStart(64, '0'),
        proof: 'dummy',
      },
    });
    expect(voteResp.status()).toBe(200);
  });

  test('registry exhaustion — second vote rejected 409 until another registration', async ({ request }) => {
    const devSign = await request.post('/api/dev/sign', {
      data: { message: 'bitwrap-create-poll:Exhaust flow', account: 6 },
    });
    const { signature, address } = await devSign.json();
    const created = await request.post('/api/polls', {
      data: { title: 'Exhaust flow', choices: ['A', 'B'], duration: 3600, creator: address, signature },
    });
    const { id: pollId } = await created.json();

    // Register one voter → one slot
    await request.post(`/api/polls/${pollId}/register`, {
      data: { commitment: '0x' + '1'.padStart(64, '0') },
    });

    // First vote consumes the slot
    const first = await request.post(`/api/polls/${pollId}/vote`, {
      data: { nullifier: '0x' + 'a'.padStart(64, '0'), voteCommitment: '0x' + 'b'.padStart(64, '0'), proof: 'p' },
    });
    expect(first.status()).toBe(200);

    // Second vote with different nullifier: rejected, no slots
    const second = await request.post(`/api/polls/${pollId}/vote`, {
      data: { nullifier: '0x' + 'c'.padStart(64, '0'), voteCommitment: '0x' + 'd'.padStart(64, '0'), proof: 'p' },
    });
    expect(second.status()).toBe(409);
    expect(await second.text()).toContain('exhausted');

    // Register another voter, then vote again
    await request.post(`/api/polls/${pollId}/register`, {
      data: { commitment: '0x' + '2'.padStart(64, '0') },
    });
    const third = await request.post(`/api/polls/${pollId}/vote`, {
      data: { nullifier: '0x' + 'c'.padStart(64, '0'), voteCommitment: '0x' + 'd'.padStart(64, '0'), proof: 'p' },
    });
    expect(third.status()).toBe(200);
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
