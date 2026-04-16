# Wallet Diagnostics Checklist

Use this checklist when a wallet signing flow (create / vote / register / close) fails on `/poll`.

## Reproduce

1. Open DevTools → Console **before** clicking the action.
2. Perform the action. Observe the banner message AND the `[wallet:<context>]` console line.
3. Capture:
   - Wallet identity reported: `MetaMask`, `Trust`, `Coinbase`, `DevWallet`, `unknown`, or `none`.
   - EIP-1193 error code: `4001` user rejected, `4100` unauthorized, `-32602` invalid params, `-32603` internal.
   - Full error object (right-click → Store as global, then `$0` to inspect).

## Common failures

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `wallet=none` in console | No injected provider. Wallet extension disabled/not installed for this origin. | Check `chrome://extensions` — enable site access. |
| `wallet=MetaMask` when you expect `Trust` | Both wallets installed; `window.ethereum` is last-writer-wins. EIP-6963 should fix this — if not, check wallet version supports EIP-6963. | Update Trust Wallet extension; try disabling MetaMask to confirm. |
| Signs OK but backend returns "signature does not match" | Wallet returned signature with unexpected `v` byte, OR address casing mismatch. | `internal/server/auth.go:VerifySignature` tries both v-parities. If still failing, capture `{message, signature, creator}` and add to `internal/server/devsign_test.go` as a regression case. |
| `code=-32603` internal error | Wallet-internal failure — often account locked or wrong network. | Unlock wallet; confirm no pending requests in wallet popup. |
| Signing prompt never appears | Extension popup blocked, OR a previous pending request is queued. | Click the extension icon in toolbar to see pending requests. |

## Collecting a bug report

Run in DevTools console on `/poll`:
```js
({
  providers6963: (() => {
    const p = [];
    window.addEventListener('eip6963:announceProvider', e => p.push(e.detail.info));
    window.dispatchEvent(new Event('eip6963:requestProvider'));
    return p;
  })(),
  windowEthereum: window.ethereum ? {
    isMetaMask: window.ethereum.isMetaMask,
    isTrust: window.ethereum.isTrust || window.ethereum.isTrustWallet,
    isCoinbaseWallet: window.ethereum.isCoinbaseWallet,
    selectedAddress: window.ethereum.selectedAddress,
  } : null,
})
```

Paste the output plus the `[wallet:...]` console line into the issue.
