// @ts-check
const { test, expect } = require('@playwright/test');

test.describe('Landing Page', () => {
  test('renders homepage with nav and hero', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveTitle(/bitwrap/i);

    // Nav links present
    const nav = page.locator('.nav-links');
    await expect(nav.getByText('Editor')).toBeVisible();
    await expect(nav.getByText('Polls')).toBeVisible();

    // Hero content
    await expect(page.locator('h1').first()).toBeVisible();
  });

  test('nav links navigate correctly', async ({ page }) => {
    await page.goto('/');
    await page.locator('.nav-links').getByText('Editor').click();
    await expect(page).toHaveURL(/\/editor/);
  });
});

test.describe('Editor Page', () => {
  test('loads editor with petri-view component', async ({ page }) => {
    await page.goto('/editor');
    await expect(page.locator('petri-view')).toBeAttached();
  });

  test('toolbar buttons are present', async ({ page }) => {
    await page.goto('/editor');
    // Check for key action buttons
    await expect(page.locator('#btn-save')).toBeVisible();
  });
});

test.describe('Poll Page', () => {
  test('loads poll interface', async ({ page }) => {
    await page.goto('/poll');
    await expect(page.locator('#poll-list')).toBeAttached();
  });
});

test.describe('API Smoke Tests', () => {
  test('GET /api/templates returns template list', async ({ request }) => {
    const resp = await request.get('/api/templates');
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.templates).toBeDefined();
    expect(data.templates.length).toBeGreaterThanOrEqual(5);
  });

  test('POST /api/solgen generates valid Solidity for each template', async ({ request }) => {
    const templates = ['erc20', 'erc721', 'erc1155', 'erc4626', 'erc5725', 'vote'];
    for (const tmpl of templates) {
      const resp = await request.post('/api/solgen', {
        data: { template: tmpl },
      });
      expect(resp.ok()).toBeTruthy();
      const data = await resp.json();
      expect(data.solidity).toContain('pragma solidity');
      expect(data.filename).toBeTruthy();
    }
  });

  test('POST /api/testgen generates test code', async ({ request }) => {
    const resp = await request.post('/api/testgen', {
      data: { template: 'erc20' },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.solidity).toContain('forge-std/Test.sol');
    expect(data.filename).toMatch(/\.t\.sol$/);
  });

  test('POST /api/genesisgen generates deploy script', async ({ request }) => {
    const resp = await request.post('/api/genesisgen', {
      data: { template: 'erc20' },
    });
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
    // ZIP magic bytes: PK\x03\x04
    expect(body[0]).toBe(0x50);
    expect(body[1]).toBe(0x4b);
  });

  test('POST /api/compile compiles .btw DSL', async ({ request }) => {
    const btw = `schema Counter {
  version "1.0"
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
    expect(data.name).toBeTruthy();
  });
});
