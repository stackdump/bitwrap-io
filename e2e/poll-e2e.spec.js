// @ts-check
// Poll e2e test — uses dev wallet with multiple signers.
// Requires server started with: ./bitwrap -port 8088 -dev -no-prover

import { test, expect } from '@playwright/test';

// Helper: sign a message using the dev endpoint with a specific account index (0-9)
async function devSign(request, message, account = 0) {
  const resp = await request.post('/api/dev/sign', {
    data: { message, account },
  });
  expect(resp.ok()).toBeTruthy();
  return resp.json();
}

// Helper: create a poll as the given account
async function createPoll(request, title, choices, account = 0) {
  const { signature, address } = await devSign(request, `bitwrap-create-poll:${title}`, account);
  const resp = await request.post('/api/polls', {
    data: { title, choices, duration: 3600, creator: address, signature },
  });
  expect(resp.ok()).toBeTruthy();
  const data = await resp.json();
  return { pollId: data.id, creator: address };
}

// Helper: close a poll as the creator
async function closePoll(request, pollId, account = 0) {
  const { signature, address } = await devSign(request, `bitwrap-close-poll:${pollId}`, account);
  const resp = await request.post(`/api/polls/${pollId}/close`, {
    data: { creator: address, signature },
  });
  expect(resp.ok()).toBeTruthy();
}

test.describe('Poll Lifecycle (dev wallet)', () => {

  test('create poll, verify, and close', async ({ request }) => {
    // Account 0 creates a poll
    const { pollId, creator } = await createPoll(request, 'Lifecycle test', ['A', 'B', 'C'], 0);
    expect(pollId).toBeTruthy();

    // Verify poll exists and is active
    const pollResp = await request.get(`/api/polls/${pollId}`);
    expect(pollResp.ok()).toBeTruthy();
    const pollData = await pollResp.json();
    const poll = pollData.poll || pollData; // handle { poll: {...} } wrapper
    expect(poll.title).toBe('Lifecycle test');
    expect(poll.choices).toEqual(['A', 'B', 'C']);
    expect(poll.status).toBe('active');
    expect(poll.creator).toBe(creator);

    // Close the poll
    await closePoll(request, pollId, 0);

    // Verify closed
    const closedResp = await request.get(`/api/polls/${pollId}`);
    const closedData = await closedResp.json();
    const closed = closedData.poll || closedData;
    expect(closed.status).toBe('closed');
  });

  test('only creator can close poll', async ({ request }) => {
    // Account 0 creates
    const { pollId } = await createPoll(request, 'Auth test', ['Yes', 'No'], 0);

    // Account 1 tries to close — should fail
    const { signature, address } = await devSign(request, `bitwrap-close-poll:${pollId}`, 1);
    const resp = await request.post(`/api/polls/${pollId}/close`, {
      data: { creator: address, signature },
    });
    expect(resp.status()).toBe(403);
  });

  test('multiple accounts create independent polls', async ({ request }) => {
    // Three different accounts each create a poll
    const poll0 = await createPoll(request, 'Poll by account 0', ['A', 'B'], 0);
    const poll1 = await createPoll(request, 'Poll by account 1', ['X', 'Y'], 1);
    const poll2 = await createPoll(request, 'Poll by account 2', ['P', 'Q'], 2);

    // Each has different creator addresses
    expect(poll0.creator).not.toBe(poll1.creator);
    expect(poll1.creator).not.toBe(poll2.creator);
    expect(poll0.creator).not.toBe(poll2.creator);

    // Each can close their own
    await closePoll(request, poll0.pollId, 0);
    await closePoll(request, poll1.pollId, 1);
    await closePoll(request, poll2.pollId, 2);
  });

  test('dev sign returns different addresses for different accounts', async ({ request }) => {
    const addrs = new Set();
    for (let i = 0; i < 5; i++) {
      const { address } = await devSign(request, 'test', i);
      expect(address).toMatch(/^0x[0-9a-f]{40}$/);
      addrs.add(address);
    }
    // All 5 should be unique
    expect(addrs.size).toBe(5);
  });
});

test.describe('Poll Voting Flow (dev wallet)', () => {

  test('register voters and view registry', async ({ request }) => {
    const { pollId } = await createPoll(request, 'Voter registry test', ['Red', 'Blue'], 4);

    // Register 3 voters with unique commitments
    for (let i = 0; i < 3; i++) {
      const resp = await request.post(`/api/polls/${pollId}/register`, {
        data: { commitment: `0x${(i + 1).toString(16).padStart(64, '0')}` },
      });
      expect(resp.ok()).toBeTruthy();
    }

    // Check registry
    const regResp = await request.get(`/api/polls/${pollId}/registry`);
    expect(regResp.ok()).toBeTruthy();
    const reg = await regResp.json();
    expect(reg.count).toBe(3);
  });

  test('view results on closed poll', async ({ request }) => {
    const { pollId } = await createPoll(request, 'Results test', ['Option A', 'Option B'], 6);

    // Close it
    await closePoll(request, pollId, 6);

    // Get results
    const resp = await request.get(`/api/polls/${pollId}/results`);
    expect(resp.ok()).toBeTruthy();
    const results = await resp.json();
    expect(results.choices).toBeDefined();
  });
});

test.describe('Poll Browser Flow (dev wallet)', () => {

  test('create poll via browser with dev wallet', async ({ page, request }) => {
    await page.goto('/poll?dev-wallet#create');

    // Wait for dev wallet to initialize
    await page.waitForFunction(() => window.ethereum && window.ethereum.selectedAddress !== '0x0000000000000000000000000000000000000000', { timeout: 5000 });

    // Fill form
    await page.locator('input[placeholder="What should we decide?"]').fill('Browser e2e poll');
    await page.locator('input[placeholder="Option 1"]').fill('Cats');
    await page.locator('input[placeholder="Option 2"]').fill('Dogs');

    // Create
    await page.getByRole('button', { name: 'Create Poll' }).click();

    // Should navigate to the poll view or show success
    await expect(page.getByText('Poll created')).toBeVisible({ timeout: 10000 });
  });

  test('view poll with choices in browser', async ({ page, request }) => {
    // Create via API using a different account to avoid rate limits
    const { pollId } = await createPoll(request, 'Browser view test', ['Alpha', 'Beta', 'Gamma'], 7);

    // Navigate to it
    await page.goto(`/poll?dev-wallet#${pollId}`);
    await expect(page.getByRole('heading', { name: 'Browser view test' })).toBeVisible();
    await expect(page.getByText('Alpha')).toBeVisible();
    await expect(page.getByText('Beta')).toBeVisible();
    await expect(page.getByText('Gamma')).toBeVisible();
    await expect(page.locator('#vote-status')).toHaveText('active');
  });
});
