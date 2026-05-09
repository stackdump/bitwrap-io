// @ts-check
// v3 (homomorphic-tally) browser E2E. Exercises the v3 client UI and
// the prove-key serving infrastructure that B5.11 wired up.
//
// Status: the create flow + UI banners are green. The full vote/close
// round-trip uncovered a witness-vs-circuit value mismatch (gnark
// reports "constraint #2459 not satisfied" mid-ElGamal-binding) that
// blocks a clean Prove call in the browser. The same JS witness
// builder passes TestWitnessV3Parity in Go, so the bug is specific
// to the live JS-witness → WASM-prove path. Tracked as a follow-up
// in the roadmap; the 'lifecycle' test below is skipped until it
// resolves.
//
// The acceptance criterion from the v3 spec is enforced by
// internal/server/v3_disk_test.go (TestV3PollDirHasNoChoiceLeakage),
// which runs a full create → vote → close lifecycle in Go and
// asserts no on-disk state leaks per-voter choices.
//
// Run: npx playwright test --project=v3
// Requires `./bitwrap -dev -key-dir <dir>` running on
// http://localhost:8088 (or override BASE_URL).

import { test } from './wallet-fixture.js';
const { expect } = test;

test.setTimeout(300_000);

test.describe('v3 maximum-privacy poll UI', () => {
    test('create v3 poll: toggle, sk backup downloads, banner shows', async ({
        page, walletAddress, request,
    }) => {
        page.on('pageerror', (err) => console.log('[browser pageerror]', err.message));

        await page.goto('/poll#create');
        await page.locator('input[placeholder="What should we decide?"]').fill('v3 e2e');
        await page.locator('input[placeholder="Option 1"]').fill('Apple');
        await page.locator('input[placeholder="Option 2"]').fill('Banana');
        await page.locator('.btn-add').click();
        await page.locator('input[placeholder="Option 3"]').fill('Cherry');

        await page.locator('#poll-max-privacy').check();

        const downloadPromise = page.waitForEvent('download', { timeout: 30_000 });
        const createResp = page.waitForResponse(
            r => r.url().endsWith('/api/polls') && r.request().method() === 'POST',
        );
        await page.getByRole('button', { name: 'Create Poll' }).click();
        const created = await createResp;
        expect(created.status()).toBe(200);
        const { id: pollId } = await created.json();

        const skBackup = await downloadPromise;
        expect(skBackup.suggestedFilename()).toMatch(/^bitwrap-poll-.+-creator-key\.json$/);

        const skLocal = await page.evaluate(
            (id) => localStorage.getItem('bitwrap-sk-creator-' + id),
            pollId,
        );
        expect(skLocal).not.toBeNull();

        const pollData = await (await request.get(`/api/polls/${pollId}`)).json();
        const poll = pollData.poll || pollData;
        expect(poll.voteSchemaVersion).toBe(3);
        expect(poll.pkCreator).toMatch(/^[0-9a-f]{64}$/);
        expect(poll.creator.toLowerCase()).toBe(walletAddress);

        await page.goto(`/poll#${pollId}`);
        await page.waitForSelector('#v3-privacy-banner', { state: 'visible', timeout: 5_000 });
        await expect(page.locator('#v2-backup-banner')).toBeHidden();

        // Reveal endpoint returns 404 for v3 polls (B5.5 contract).
        const revealAttempt = await request.post(`/api/polls/${pollId}/reveal`, {
            data: { nullifier: '0x0', voteChoice: 0, voterSecret: '0' },
        });
        expect(revealAttempt.status()).toBe(404);
    });

    test('v2 poll without max-privacy toggle uses old banner', async ({ page, request }) => {
        await page.goto('/poll#create');
        await page.locator('input[placeholder="What should we decide?"]').fill('v2 baseline');
        await page.locator('input[placeholder="Option 1"]').fill('Yes');
        await page.locator('input[placeholder="Option 2"]').fill('No');

        const createResp = page.waitForResponse(
            r => r.url().endsWith('/api/polls') && r.request().method() === 'POST',
        );
        await page.getByRole('button', { name: 'Create Poll' }).click();
        const { id: pollId } = await (await createResp).json();

        const pollData = await (await request.get(`/api/polls/${pollId}`)).json();
        const poll = pollData.poll || pollData;
        expect(poll.voteSchemaVersion).toBe(2);
        expect(poll.pkCreator).toBeFalsy();

        await page.goto(`/poll#${pollId}`);
        await page.waitForSelector('#v2-backup-banner', { state: 'visible', timeout: 5_000 });
        await expect(page.locator('#v3-privacy-banner')).toBeHidden();
    });

    // Full create → register → vote → close lifecycle. The underlying
    // gnark-wasm prove blocker (issue #3) is now worked around by
    // recompiling cs in-browser via `loadKeysFreshCS`. The test body
    // itself still needs to be written — voter registration + ballot
    // submission + creator close from a real Chromium tab takes
    // multiple minutes (one-time circuit compile per browser session
    // is ~50s; per-vote prove is ~10s). Until we have a sensible CI
    // runner for that, this stays skipped — but unblocked.
    test.skip('create → register → vote → close (browser proving)', async () => {
        // TODO: implement now that issue #3 is unblocked.
    });
});
