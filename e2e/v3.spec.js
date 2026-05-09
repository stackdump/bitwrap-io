// @ts-check
// v3 (homomorphic-tally) browser E2E.
//
// Scope: the create-poll v3 UI flow (toggle, banner, sk_creator
// backup download, server persistence) and the active-poll v3 banner
// switching. The end-to-end vote/close round-trip is gated on
// client-side proving keys being served from /api/keys/{circuit}.*
// (tracked as B5.11 in docs/phase-b-roadmap.md). Until that lands,
// the WASM worker can't prove voteCastHomomorphic_8 in the browser
// because the server only exposes verifying keys, not the cs+pk pair
// needed for proving.
//
// Run: npx playwright test --project=v3
// Requires `./bitwrap -dev` running on http://localhost:8088 (or
// override BASE_URL).

import { test } from './wallet-fixture.js';
const { expect } = test;

test.setTimeout(60_000);

test.describe('v3 maximum-privacy poll create flow', () => {
    test('create v3 poll: toggle, sk backup downloads, banner shows', async ({
        page, walletAddress, request,
    }) => {
        page.on('pageerror', (err) => console.log('[browser pageerror]', err.message));

        // -- 1. Create the v3 poll -----------------------------------------
        await page.goto('/poll#create');
        await page.locator('input[placeholder="What should we decide?"]').fill('v3 e2e');
        await page.locator('input[placeholder="Option 1"]').fill('Apple');
        await page.locator('input[placeholder="Option 2"]').fill('Banana');
        await page.locator('.btn-add').click();
        await page.locator('input[placeholder="Option 3"]').fill('Cherry');

        await page.locator('#poll-max-privacy').check();

        // Backup file download fires synchronously after the create
        // response — set up the listener before clicking submit.
        const downloadPromise = page.waitForEvent('download', { timeout: 30_000 });

        const createResp = page.waitForResponse(
            r => r.url().endsWith('/api/polls') && r.request().method() === 'POST',
        );
        await page.getByRole('button', { name: 'Create Poll' }).click();
        const created = await createResp;
        expect(created.status()).toBe(200);
        const { id: pollId } = await created.json();
        expect(pollId).toBeTruthy();

        // The backup file should download with the poll-id-prefixed name.
        const download = await downloadPromise;
        expect(download.suggestedFilename()).toMatch(/^bitwrap-poll-.+-creator-key\.json$/);

        // localStorage holds the sk under the per-poll key.
        const skLocal = await page.evaluate(
            (id) => localStorage.getItem('bitwrap-sk-creator-' + id),
            pollId,
        );
        expect(skLocal).not.toBeNull();
        expect(/^[0-9]+$/.test(/** @type {string} */ (skLocal))).toBe(true);

        // -- 2. Server persisted the v3 metadata ---------------------------
        const pollData = await (await request.get(`/api/polls/${pollId}`)).json();
        const poll = pollData.poll || pollData;
        expect(poll.voteSchemaVersion).toBe(3);
        expect(poll.pkCreator).toMatch(/^[0-9a-f]{64}$/);
        expect(poll.creator.toLowerCase()).toBe(walletAddress);

        // -- 3. Vote view shows the v3 banner, not the v2 one -------------
        await page.goto(`/poll#${pollId}`);
        await page.waitForSelector('#v3-privacy-banner', { state: 'visible', timeout: 5_000 });
        await expect(page.locator('#v2-backup-banner')).toBeHidden();

        // -- 4. Reveal endpoint returns 404 for v3 polls (B5.5 contract) --
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

        // Toggle deliberately left unchecked.
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
});

// FOLLOW-UP: when B5.11 lands, replace the gating doc-comment above
// with the full create → register → vote → close → tally flow. The
// scaffolding to do this is already in place — the only missing piece
// is the WASM worker's loadKeys call against /api/keys/{circuit}.*
// before workerProve.
