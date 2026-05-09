// @ts-check
// Diagnostic: capture the v3 witness JSON the browser sends to the
// WASM prover, so we can replay it server-side. Skipped from CI.
//
// Run: npx playwright test --project=v3 v3_dump_witness.spec.js
// Output goes to /tmp/v3-witness-dump.json.

import { test } from './wallet-fixture.js';
import { writeFileSync } from 'node:fs';

test.setTimeout(180_000);

test('dump v3 witness', async ({ page }) => {
    let dumped = null;
    page.on('console', (msg) => {
        const text = msg.text();
        if (text.startsWith('V3_WITNESS_DUMP ')) {
            dumped = text.slice('V3_WITNESS_DUMP '.length);
        }
    });
    page.on('pageerror', (err) => console.log('[browser pageerror]', err.message));

    // Create v3 poll.
    await page.goto('/poll#create');
    await page.locator('input[placeholder="What should we decide?"]').fill('dump');
    await page.locator('input[placeholder="Option 1"]').fill('A');
    await page.locator('input[placeholder="Option 2"]').fill('B');
    await page.locator('.btn-add').click();
    await page.locator('input[placeholder="Option 3"]').fill('C');
    await page.locator('#poll-max-privacy').check();

    page.on('download', () => {}); // accept the sk backup
    const created = await Promise.all([
        page.waitForResponse(r => r.url().endsWith('/api/polls') && r.request().method() === 'POST'),
        page.getByRole('button', { name: 'Create Poll' }).click(),
    ]).then(([r]) => r.json());
    const pollId = created.id;

    await page.goto(`/poll#${pollId}`);
    await page.waitForSelector('#v3-privacy-banner', { state: 'visible', timeout: 5_000 });

    // Register
    const reg = page.waitForResponse(r => r.url().includes(`/${pollId}/register`));
    await page.getByRole('button', { name: /Register to Vote/i }).click();
    await reg;

    // Click Cast Vote — this triggers the witness dump on console
    // before the WASM prove call. We don't need prove to succeed.
    await page.locator('.choice-option[data-idx="1"]').click();
    await page.getByRole('button', { name: 'Cast Vote' }).click();

    // Wait until the dump shows up.
    for (let i = 0; i < 60; i++) {
        if (dumped) break;
        await page.waitForTimeout(1000);
    }
    if (!dumped) throw new Error('witness dump did not appear within 60s');
    writeFileSync('/tmp/v3-witness-dump.json', JSON.stringify({
        pollId,
        witness: JSON.parse(dumped),
    }, null, 2));
    console.log('wrote /tmp/v3-witness-dump.json');
});
