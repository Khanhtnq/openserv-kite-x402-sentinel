# OpenServ Kite x402 Sentinel

> **Dual-Authority Autonomous Payment Firewall & x402 v2 Settlement Gateway**  
> Powered by **OpenServ Agent SDK (`@openserv-labs/sdk`)**, **SERV Reasoning (`serv_prompt_guard` + `serv_shadow_agent` + `-serv-multipath`)**, and **Deterministic Kite Agent Passport Session Mandates** across **Kite Mainnet (`2366`)**, **Kite Testnet (`2368`)**, and **Base Mainnet (`8453`)**.

[![Live Demo Playground](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-blue?style=for-the-badge&logo=github)](https://khanhtnq.github.io/openserv-kite-x402-sentinel/)
[![Tests](https://img.shields.io/badge/Vitest-53%2F53%20Passing-emerald?style=for-the-badge&logo=vitest)](https://github.com/Khanhtnq/openserv-kite-x402-sentinel)
[![OpenServ](https://img.shields.io/badge/OpenServ-Edition%2002%20Kite%20Track-orange?style=for-the-badge)](https://www.openserv.ai/hackathon-2)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Worker%20Ready-f38020?style=for-the-badge&logo=cloudflare)](https://github.com/Khanhtnq/openserv-kite-x402-sentinel)

---

## 1. System Architecture

```mermaid
flowchart TD
    subgraph Merchant ["Untrusted Merchant / x402 Target"]
        API["HTTP Endpoint (GET/POST)"]
        Challenge402["HTTP 402 Payment Required\naccepts: [asset, amount, payTo, network]"]
    end

    subgraph SentinelCore ["OpenServ Kite x402 Sentinel (Dual-Authority)"]
        subgraph Layer1 ["Authority Tier 1: Deterministic Gates"]
            SSRF["SSRF / URL Sanitizer\n(blocks userinfo, loopback, private IPv4/IPv6)"]
            KiteSession["Kite Passport Session Mandate\n(scoped method, host, prefix, TTL, per-tx cap, total cap)"]
            EVMValidation["Pre-Sign EVM & EIP-712 Firewall\n(decodeCalldata, block unlimited approve / EIP-7702 hijacks)"]
            Idempotency["Atomic Idempotency Engine\n(in-memory fingerprinting, replay defense)"]
        end

        subgraph Layer2 ["Authority Tier 2: OpenServ SERV Reasoning Engine"]
            PromptGuard["serv_prompt_guard\n(quarantines injected prompt payloads in notes/memos)"]
            ShadowAgent["serv_shadow_agent\n(secondary validation & value-justification loop)"]
            Multipath["-serv-multipath Inference\n(parallel trajectory search on gpt-5.4-mini)"]
            RogueClamp["Strict Policy Clamp\n(clampedBudgetMultiplier <= 1.0, rogue model defense)"]
        end

        Ledger["Dual-Authority Audit Ledger\nDeterministic Fact vs SERV Explanation (SHA-256 Digest)"]
    end

    subgraph SettlementLayer ["Onchain Settlement Networks"]
        KiteMain["KiteAI Mainnet (eip155:2366)\nUSDC.e (6 dec) | kitescan.ai"]
        KiteTest["KiteAI Testnet (eip155:2368)\npieUSD (18 dec ceiling rounded) | testnet.kitescan.ai"]
        BaseMain["Base Mainnet (eip155:8453)\nUSDC (6 dec) | basescan.org"]
    end

    API -->|402 Challenge| Challenge402
    Challenge402 --> SSRF
    SSRF --> KiteSession
    KiteSession --> EVMValidation
    EVMValidation --> Idempotency
    Idempotency --> PromptGuard
    PromptGuard --> ShadowAgent
    ShadowAgent --> Multipath
    Multipath --> RogueClamp
    RogueClamp --> Ledger

    Ledger -->|APPROVED: Signed Payment Header| SettlementLayer
    SettlementLayer --> KiteMain
    SettlementLayer --> KiteTest
    SettlementLayer --> BaseMain
```

An architectural SVG diagram is available in [`docs/architecture.svg`](docs/architecture.svg).

---

## 2. Core Invariants & Security Guarantees

1. **Dual-Authority Separation**:
   - **Deterministic TypeScript Policy** is the sole binding authority on spending limits, endpoint scoping, and transaction execution.
   - **OpenServ SERV Reasoning** provides intelligent contextual evaluation, prompt-injection defense, and value analysis.
   - A rogue or hallucinating LLM proposing an inflated budget multiplier (`simulateRogueModelProposal: { proposedAmountMultiplier: 10 }`) is strictly clamped (`clampedBudgetMultiplier <= 1.0`) and blocked by deterministic policy gates.
2. **Deterministic Ceiling Rounding (`atomicToUsdMicros`)**:
   - For high-precision tokens (such as 18-decimal `pieUSD` on Kite Testnet), rounding uses `((amountAtomic * 1_000_000n + scale - 1n) / scale)`.
   - Sub-micro dust can never bypass session spending limits or accumulate unaccounted drain.
3. **Pre-Sign EVM & EIP-712 Calldata Firewall**:
   - Blocks unlimited ERC-20 token approvals (`>= 2^128 - 1`).
   - Blocks EIP-7702 batch delegation hijacks in transaction `authorizationList`.
   - Blocks `setApprovalForAll` NFT draining patterns.
   - Blocks EIP-712 permit and EIP-3009 messages if the spender/payee does not match the authorized merchant `payTo`.
4. **Active Prompt Injection Quarantine**:
   - Integrated with OpenServ `serv_prompt_guard` tool declaration and deterministic pre-check scanning.
   - Detects adversarial injection payloads in `merchantUntrustedNote` or challenge metadata, quarantining them with `BLOCKED_PROMPT_INJECTION` before LLM processing.
5. **SSRF & Endpoint Scoping**:
   - Validates all merchant URLs: enforces `https://`, strips credentials/userinfo (`@`), and blocks private IPv4/IPv6 ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, link-local, loopback).
   - Enforces exact HTTP method, target hostname, and pathname prefix matching the Kite Agent Passport session delegation.

---

## 3. Deployment & Runtime Modes

Sentinel is designed for flexibility across different agent environments:

| Mode | Command / Path | Description |
|:---|:---|:---|
| **Interactive Live Demo** | [`https://khanhtnq.github.io/openserv-kite-x402-sentinel/`](https://khanhtnq.github.io/openserv-kite-x402-sentinel/) | Zero-install interactive browser playground executing client-side simulations of prompt-injection defense, rogue model clamping, and EVM calldata audits. |
| **OpenServ Agent SDK** | `npm run agent` | Runs as an autonomous agent on OpenServ network via `@openserv-labs/sdk` registering `audit_kite_x402_payment`, `simulate_evm_firewall`, and `compile_kite_delegation` capabilities. |
| **Node.js Gateway / Server** | `npm start` | Production HTTP server with interactive web workbench, `GET /.well-known/x402`, and `POST /v1/sentinel/audit`. |
| **Terminal CLI Demo** | `npm run demo` | Verifies all 5 core security scenarios in the terminal with zero network dependencies. |
| **Stateless Edge Worker** | `src/worker.ts` / `wrangler.toml` | Low-latency Cloudflare Worker deployable directly to the edge for distributed AI agent clusters. |

---

## 4. Quickstart & Installation

### Prerequisites
- Node.js `>= 20.0.0`
- npm `>= 10.0.0`

```bash
# Clone the repository
git clone https://github.com/Khanhtnq/openserv-kite-x402-sentinel.git
cd openserv-kite-x402-sentinel

# Install dependencies
npm install

# Run the complete test suite (53 unit + integration + adversarial + edge worker tests)
npm test

# Run TypeScript compilation check
npm run typecheck

# Run the live interactive terminal demo
npm run demo
```

---

## 5. Configuration & Environment Variables

Copy `.env.example` to `.env` and configure your keys:

```bash
cp .env.example .env
```

| Environment Variable | Description | Default |
|:---|:---|:---|
| `SENTINEL_PAY_TO` | Canonical EVM payment recipient address | `0xcbEDbeCC127a32217075Ff40f16Ec804aa1E0533` |
| `KITE_NETWORK` | Default Kite network (`mainnet` or `testnet`) | `mainnet` |
| `SELLER_PRICE_USD` | Baseline seller price for audit endpoints | `0.001` |
| `OPENSERV_API_KEY` | OpenServ API key for live SERV Reasoning calls | Optional (falls back to deterministic simulation) |
| `SERV_BASE_URL` | OpenServ Reasoning API endpoint | `https://inference-api.openserv.ai/v1` |
| `SERV_MODEL` | SERV Reasoning model identifier | `gpt-5.4-mini-serv-multipath` |
| `PORT` | Local HTTP server port | `7378` |

---

## 6. HTTP & OpenServ Agent Integration

### Running the HTTP Settlement Gateway
```bash
npm start
```

Available endpoints:
- `GET /health`: Health status and registered settlement networks.
- `GET /.well-known/x402`: Public x402 service discovery manifest.
- `POST /v1/sentinel/audit`: Payment audit and settlement authorization endpoint (returns HTTP 402 challenge when unpaid, HTTP 200 when authorized with demo flag or valid payment header).

### Running as an OpenServ Platform Agent
```bash
npm run agent
```
Registers the Sentinel agent with `@openserv-labs/sdk`, enabling other autonomous agents on the OpenServ network to request secure payment audits, session compilations, and pre-sign calldata verifications.
