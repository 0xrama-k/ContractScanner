# ContractScanner — Hackathon Submission

_Stablecoin Commerce Stack Challenge · Circle & Arc_

---

## 1. Title and short description

**ContractScanner — pay-per-scan Solidity security auditing, settled in USDC on Arc.**

ContractScanner is a pay-per-use AI security service. A developer pastes or uploads
a Solidity contract and pays a small, fixed **USDC** fee on **Circle's Arc** testnet;
once the on-chain payment confirms, the backend runs Slither static analysis inside a
network-disabled Docker sandbox, normalizes and risk-scores the findings, optionally
enriches them with an LLM explanation layer, and returns an actionable report
(viewable in-app and exportable as JSON or Markdown). Each scan is one metered,
USDC-settled unit of compute — a clean example of a real-time, pay-per-inference
service running on programmable stablecoin rails.

## 2. Track

**Track 4 — Best Agentic Economy Experience on Arc.**

Direct fit with the track's "pay-per-inference AI agents that pay for each model
response or dataset access in real time" example: each security scan is metered and
paid for in USDC at the moment of use, with the analysis (including an LLM layer)
kicked off automatically the instant the payment settles on Arc.

## 3. Circle Developer Account email

`ramazankaratas626@gmail.com`
_(Replace if your Circle Console account uses a different email.)_

## 4. Circle products used on Arc

- [x] **USDC** — native settlement rail on Arc; the per-scan fee is paid and
      collected as native USDC value via `pay(bytes32)`.
- [ ] Wallets — _not used; the app connects user-owned injected wallets via EIP-6963
      (MetaMask, Rabby, etc.). See roadmap below._
- [ ] Gateway · [ ] CCTP/Bridge Kit · [ ] USYC · [ ] StableFX · [ ] Nanopayments

## 5. Functional MVP and architecture diagram

- **Working frontend + backend:** yes — Rust/Axum backend, PostgreSQL, Dockerized
  Slither sandbox, and a single-page frontend with an EIP-6963 wallet flow that pays
  in USDC on Arc.
- **Architecture diagram:** see [`README.md`](README.md#architecture) and
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (Mermaid, GitHub-rendered).

## 6. Video demonstration

https://drive.google.com/file/d/1p5cYC1xNCt9HxHwnUOp86WR6IbvDfagt/view?usp=drive_link

Walk-through of creating a scan, paying in USDC on Arc, and reading the generated
report.

## 7. GitHub / code repository

https://github.com/0xrama-k/ContractScanner

Setup and Circle-integration details are in [`README.md`](README.md) (see
"Enabling the live USDC gate on Arc").

## 8. Demo application URL

http://www.gaziblockchain.tech/

---

## Circle Product Feedback

### Why we chose these products for our use case

We chose **USDC on Arc** because a security scan is a discrete, metered unit of
compute — the textbook shape for a pay-per-use rail. Two Arc properties made it the
right fit:

1. **USDC is the native asset on Arc**, so the scan fee is collected directly through
   a `payable` function's `msg.value`. There is no ERC-20 `approve` + `transferFrom`
   round-trip, which means **one wallet confirmation per scan** and a much simpler
   contract (`contracts/ScanPayments.sol` is import-free and self-contained).
2. **Deterministic finality** lets the backend treat a confirmed `ScanPaid` event as
   settlement and immediately transition the scan from `awaiting_payment` to `queued`,
   producing a genuine real-time "pay → scan starts" experience.

Dollar-denominated, fixed pricing (10 USDC/scan) also keeps the UX legible for
developers who are not crypto-native.

### What worked well during development

- **Native USDC value transfer** collapsed our payment integration to a single
  `payable` call. Our original prototype targeted a native-gas-token chain, and
  migrating to Arc was nearly mechanical precisely because USDC behaves as the native
  asset — the payment contract's logic did not have to change.
- **EVM compatibility** meant our existing tooling (Foundry `forge create`, raw
  `eth_getLogs`/`eth_blockNumber` JSON-RPC polling in the watcher, EIP-6963 wallet
  discovery, `wallet_addEthereumChain`) worked against Arc with only endpoint and
  chain-id changes.
- Clear, stable **contract addresses and network parameters** in the Arc docs made
  wiring up the RPC, chain id (`5042002`), and explorer straightforward.

### What could be improved

- **The 18-vs-6 decimal split for native USDC vs. the ERC-20 interface is a sharp
  edge.** `msg.value` is 18-decimal while `USDC.balanceOf` is 6-decimal for the same
  underlying balance. It's easy to write an off-by-10^12 bug here; we'd love a
  first-class helper / clearly flagged constant in the docs and SDKs, plus louder
  warnings around `balanceOf` reading `0` for small native balances.
- **Faucet + onboarding discoverability.** Because USDC doubles as the gas token,
  a brand-new deployer needs testnet USDC before they can do anything. A single
  "connect wallet on Arc testnet" quickstart that funds gas and drops you at a
  deployed contract would shorten first-run time significantly.
- **Public-RPC `eth_getLogs` range limits** aren't documented in one obvious place;
  we kept a conservative 100-block window to be safe. Publishing the exact limits
  (and recommended pagination) per RPC provider would help event-indexing backends.

### Recommendations to make the product / developer experience more seamless

- Ship a tiny reference **"pay-per-use / metered service"** sample (payable-fee
  contract + backend event watcher) — it's a common agentic-economy pattern and maps
  directly onto Arc's native-USDC model.
- Provide official **decimal-conversion utilities** (native ↔ ERC-20) in the JS/Rust
  SDKs so builders never hand-roll the `10^12` factor.
- Offer a **hosted testnet event-indexer or webhooks for contract events**, so
  backends don't have to poll `eth_getLogs`; our watcher would collapse to a webhook
  handler.

### Roadmap (Circle products we'd add next)

- **Circle Wallets** — embedded wallets so non-crypto-native users can pay for a scan
  without installing a browser extension.
- **Circle Gateway / CCTP** — let teams fund scans from USDC held on other chains and
  route settlement/treasury movement for a hosted, multi-tenant version.
- **Nanopayments** — sub-cent, per-detector or streaming pricing (pay only for the
  analyzers you run) instead of a flat per-scan fee.
