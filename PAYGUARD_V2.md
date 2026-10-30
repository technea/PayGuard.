# PayGuard 2.0 — Base-first MVP

## Current implementation status

This branch is an incremental upgrade of the existing PayGuard project. The original `main` branch is unchanged.

### Implemented in the first V2 slice

- Added a Base Sepolia wallet panel to the existing dashboard.
- Connects through an injected EIP-1193 provider (for example, MetaMask).
- Reads the connected account and active chain ID.
- Detects Base Sepolia (chain ID 84532).
- Offers a wallet-approved network switch and adds Base Sepolia if the wallet reports that the chain is unknown.
- Handles account and chain changes while the page is open.
- Provides a page-local clear action and explains that site permissions must be revoked in the wallet itself.
- Added a Base Sepolia policy template builder for an HTTPS resource, trusted recipient, token contract, maximum atomic amount, Base Sepolia network, exact scheme, and timeout.
- The builder validates the URL and EVM address/amount formats, then populates the existing Payment Guard policy editor. The user must still provide the real x402 requirements to evaluate.

### Explicit security boundaries

- This is a wallet connection and network-verification feature only.
- It does not request signatures, send transactions, read private keys, or move funds.
- It does not enforce spending limits or prevent a connected wallet from paying elsewhere.
- The existing Payment Guard verdict remains advisory unless a downstream payment executor independently enforces it.
- No claim is made that a connected EOA is a restricted wallet or that a smart contract policy is active.

## Base Sepolia configuration

- Chain ID (decimal): `84532`
- Chain ID (hex): `0x14a34`
- Native currency: `ETH`
- RPC: `https://sepolia.base.org`
- Explorer: `https://sepolia.basescan.org`

## Manual acceptance checklist

1. Open the dashboard in a browser with MetaMask or another EIP-1193 wallet.
2. Open the **Base Wallet** tab.
3. With no wallet installed, confirm a clear unsupported-wallet message appears.
4. Connect a wallet and approve the account request.
5. On Base Sepolia, confirm the account and network are displayed.
6. On another EVM network, confirm the wrong-network warning appears.
7. Use **Switch to Base Sepolia** and approve the network switch in the wallet.
8. Change accounts or networks in the wallet and confirm the page updates.
9. Use **Clear Connection** and confirm the page clears its selected account. Verify the UI does not claim that wallet site permission was revoked.
10. Confirm no signature or transaction approval appears at any point.

## Validation status

- GitHub Actions CI passed on the V2 pull request: 55 tests passed, distributable syntax check passed, and plugin export check passed.
- Dashboard inline JavaScript syntax was checked and passed.
- Dashboard tab section counts were checked and balanced.
- Browser wallet interaction still needs manual testing with MetaMask on Base Sepolia.

## Next implementation milestones

1. Extract and test wallet/network helpers independently; add browser-level tests where a wallet provider can be mocked.
2. Add server-side and automated tests for the Base Sepolia policy template and validation UX.
3. Add privacy-conscious local audit events for checks and user decisions; do not persist secrets or raw sensitive URLs.
4. Design and test a restricted smart-contract spending path on Base Sepolia before describing any payment blocking as enforced.
5. Add persistent policies and production-grade rate limiting only after choosing a suitable storage/runtime architecture.

## Deferred

- RAG and company PDF ingestion
- NEAR and other chain adapters
- Paid credits, subscriptions, and billing
- Production custody or signing
- Mainnet payment enforcement

These are deliberately outside the first Base-first MVP slice.
