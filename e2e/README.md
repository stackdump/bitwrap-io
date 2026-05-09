# bitwrap-io e2e tests

Three suites with different purposes.

## Fast suite

Uses the dev-wallet shim (`public/dev-wallet.js` + `/api/dev/sign` server endpoint).
Runs headless in ~2s.

```bash
make run &
cd e2e && npm test
```

Covers: API smoke tests, poll lifecycle, dev-wallet browser flows.

## Real-wallet suite

Uses a Playwright fixture (`wallet-fixture.js`) that injects a `window.ethereum`
mock performing real secp256k1 signing client-side (same crypto as
`public/dev-wallet.js`). Signatures are cryptographically identical to what
MetaMask / Trust Wallet produce and flow through the backend's
`VerifySignature` for address recovery.

This is the authoritative test for the `window.ethereum` → `personal_sign` →
`VerifySignature` path. A regression in the JS crypto (e.g. the modInverse
sign bug that prompted this suite) will be caught here.

```bash
make test-e2e-wallet
```

Or manually:
```bash
./bitwrap -port 8088 -dev -no-prover &
cd e2e && npx playwright test --project=wallet
```

### Why not Synpress / a real MetaMask extension?

Tried it first — Synpress v4 is in alpha with unstable MetaMask 13.13.1
compatibility, and each test needs a headed browser + extension cache rebuild
(~30s per run). The Playwright fixture approach runs headless in <1s, catches
the same class of bug (proven: the modInverse fix), and has zero external
dependencies. A manual Trust Wallet / MetaMask smoke test before release
covers the extension-UX side.

## Prod suite

Runs against any deployment with no `-dev` flag. Default target is
`https://bitwrap.io` (override with `PROD_URL=...`).

```bash
cd e2e && npm run test:prod
```

Constraints worked around:
- No `/api/dev/sign` server endpoint — wallet flows sign via `nodeWallet()`,
  exported from `wallet-fixture.js`, using the same secp256k1 + EIP-191
  primitives the in-browser dev-wallet uses.
- Per-IP rate limiter (5 polls/hr) — single worker, only one wallet test
  creates a poll. A 429 response from `/api/polls` causes that test to
  `test.skip()` rather than fail. Each run uses `freshPrivateKey()` so the
  per-wallet bucket is never the bottleneck.
- Polls created by the suite are tagged `playwright-prod ...` and expire
  after 60 minutes. There is no delete endpoint to clean up explicitly.

## Debugging a wallet failure

See `diagnostics.md` for the checklist when manual wallet signing fails in the
browser.
