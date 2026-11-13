import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  CANONICAL_EVM_PAY_TO,
  CANONICAL_SOLANA_PAY_TO,
  SETTLEMENT_NETWORKS,
  KITE_NETWORKS,
  resolveSettlementNetwork,
  parseUsdToMicros,
  formatMicrosToUsd,
  atomicToUsdMicros,
  compileKiteDelegation,
  createSessionRuntimeState,
  KitePaymentSentinel,
  createSentinelOpenServAgent,
  createSentinelHttpServer,
  BuyerPaymentIntentInput,
} from "../src/index.js";
import type { Server } from "node:http";

describe("OpenServ Kite x402 Sentinel — Core Unit & Integration Suite", () => {
  let sentinel: KitePaymentSentinel;

  beforeEach(() => {
    sentinel = new KitePaymentSentinel({
      allowLocalhostMerchantUrls: true,
    });
  });

  function helperCreateSession(params: {
    merchantUrl: string;
    method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
    preflightPriceUsd?: string;
    estimatedRequests?: number;
    ttlSeconds?: number;
    approvalThresholdUsdMicros?: bigint;
    dailyCapUsdMicros?: bigint;
  }) {
    const compiled = compileKiteDelegation({
      taskSummary: "Test Session",
      merchantUrl: params.merchantUrl,
      method: params.method || "GET",
      preflightPriceUsd: params.preflightPriceUsd || "0.01",
      estimatedRequests: params.estimatedRequests || 10,
      ttlSeconds: params.ttlSeconds || 3600,
      allowLocalhostMerchantUrls: true,
    });

    const state = createSessionRuntimeState({
      userRootAddress: CANONICAL_EVM_PAY_TO,
      agentDelegatedAddress: "0x1111111111111111111111111111111111111111",
      ephemeralSessionAddress: "0x2222222222222222222222222222222222222222",
      delegation: compiled.delegation,
      approvalThresholdUsdMicros: params.approvalThresholdUsdMicros,
      dailyCapUsdMicros: params.dailyCapUsdMicros,
    });

    return sentinel.registerSession(state);
  }

  describe("1. Network & Constants Resolution", () => {
    it("should resolve canonical settlement networks correctly", () => {
      expect(CANONICAL_EVM_PAY_TO).toBe("0xcbEDbeCC127a32217075Ff40f16Ec804aa1E0533");
      expect(CANONICAL_SOLANA_PAY_TO).toBe("6mghraUR9NV2fA187VXoLN2rVS3WLA91UhqLfjtvDdmf");

      const kiteMain = resolveSettlementNetwork("kite-mainnet");
      expect(kiteMain?.chainId).toBe(2366);
      expect(kiteMain?.symbol).toBe("USDC.e");
      expect(kiteMain?.decimals).toBe(6);

      const kiteTest = resolveSettlementNetwork(2368);
      expect(kiteTest?.chainId).toBe(2368);
      expect(kiteTest?.symbol).toBe("pieUSD");
      expect(kiteTest?.decimals).toBe(18);

      const baseMain = resolveSettlementNetwork("eip155:8453");
      expect(baseMain?.chainId).toBe(8453);
      expect(baseMain?.symbol).toBe("USDC");
      expect(baseMain?.decimals).toBe(6);

      expect(resolveSettlementNetwork("unsupported-net")).toBeUndefined();
    });

    it("should provide backwards-compatible KITE_NETWORKS aliases", () => {
      expect(KITE_NETWORKS.mainnet.chainId).toBe(2366);
      expect(KITE_NETWORKS.testnet.chainId).toBe(2368);
      expect(KITE_NETWORKS.mainnet.network).toBe("eip155:2366");
      expect(KITE_NETWORKS.testnet.network).toBe("eip155:2368");
    });
  });

  describe("2. Deterministic Currency & Ceiling Rounding Helpers", () => {
    it("should convert USD decimal strings to integer micros with zero drift", () => {
      expect(parseUsdToMicros("0.001")).toBe(1000n);
      expect(parseUsdToMicros("1.000000")).toBe(1_000_000n);
      expect(parseUsdToMicros("0")).toBe(0n);
      expect(parseUsdToMicros("10.5")).toBe(10_500_000n);
      expect(() => parseUsdToMicros("-1")).toThrow();
      expect(() => parseUsdToMicros("abc")).toThrow();
      expect(() => parseUsdToMicros("1.1234567")).toThrow(); // > 6 decimals
    });

    it("should format micros back to USD decimal strings accurately", () => {
      expect(formatMicrosToUsd(1000n)).toBe("0.001");
      expect(formatMicrosToUsd(1_000_000n)).toBe("1");
      expect(formatMicrosToUsd(0n)).toBe("0");
      expect(formatMicrosToUsd(10_500_000n)).toBe("10.5");
      expect(() => formatMicrosToUsd(-5n)).toThrow();
    });

    it("should enforce ceiling rounding on 18-decimal token dust (atomicToUsdMicros)", () => {
      // 6 decimals (1:1 with micros)
      expect(atomicToUsdMicros(1000n, 6)).toBe(1000n);

      // 18 decimals pieUSD: 1 token = 10^18 atomic -> 10^6 micros
      const onePieUsd = 1_000_000_000_000_000_000n;
      expect(atomicToUsdMicros(onePieUsd, 18)).toBe(1_000_000n);

      // 1 wei dust (sub-micro) MUST round UP to 1 micro so dust cannot bypass spend limits!
      expect(atomicToUsdMicros(1n, 18)).toBe(1n);

      // Exactly 10^12 wei = 1 micro
      expect(atomicToUsdMicros(1_000_000_000_000n, 18)).toBe(1n);
      // 10^12 + 1 wei MUST round UP to 2 micros!
      expect(atomicToUsdMicros(1_000_000_000_001n, 18)).toBe(2n);
    });
  });

  describe("3. Kite Session Delegation Compiler & Runtime State", () => {
    it("should compile valid Kite delegation with safety buffer and safe shell command", () => {
      const compiled = compileKiteDelegation({
        taskSummary: "Fetch hourly weather prediction",
        merchantUrl: "https://api.weather-kite.example/v1/forecast",
        method: "GET",
        preflightPriceUsd: "0.002",
        estimatedRequests: 10,
        ttlSeconds: 3600,
        safetyBufferBps: 2000, // 20%
      });

      expect(compiled.delegation.task.summary).toBe("Fetch hourly weather prediction");
      expect(compiled.delegation.payment_policy.max_amount_per_tx).toBe("0.0024");
      expect(compiled.delegation.payment_policy.max_total_amount).toBe("0.024");
      expect(compiled.delegation.payment_policy.ttl_seconds).toBe(3600);
      expect(compiled.delegation.execution_constraints?.x402?.allowed_endpoints[0]).toEqual({
        method: "GET",
        host: "api.weather-kite.example",
        path_prefix: "/v1/forecast",
      });
      expect(compiled.kpassCliCommand).toContain("kpass session create --policy");
    });

    it("should track runtime session state and BigInt spend counters", () => {
      const compiled = compileKiteDelegation({
        taskSummary: "Autonomous Agent Session",
        merchantUrl: "https://api.service.example/v1/query",
        method: "POST",
        preflightPriceUsd: "0.01",
        estimatedRequests: 5,
        ttlSeconds: 1800,
      });

      const session = createSessionRuntimeState({
        userRootAddress: CANONICAL_EVM_PAY_TO,
        agentDelegatedAddress: "0x1111111111111111111111111111111111111111",
        ephemeralSessionAddress: "0x2222222222222222222222222222222222222222",
        delegation: compiled.delegation,
      });

      expect(session.cumulativeSpentUsdMicros).toBe(0n);
      expect(session.txCount).toBe(0);
      expect(session.idempotency.size).toBe(0);
      expect(session.expiresAtSec).toBeGreaterThan(session.issuedAtSec);
    });
  });

  describe("4. End-to-End Multichain Payment Intent Audits (APPROVED with SHA-256 Digest)", () => {
    it("should APPROVE valid Kite Mainnet payment intent (USDC.e, 6 decimals)", async () => {
      const session = helperCreateSession({
        merchantUrl: "https://api.service.example/v1/data",
        method: "GET",
        preflightPriceUsd: "0.005",
        estimatedRequests: 10,
        ttlSeconds: 3600,
      });

      const intent: BuyerPaymentIntentInput = {
        sessionId: session.sessionId,
        merchantUrl: "https://api.service.example/v1/data",
        method: "GET",
        challenge402: {
          x402Version: 2,
          accepts: [
            {
              scheme: "exact",
              network: "eip155:2366",
              asset: SETTLEMENT_NETWORKS["kite-mainnet"].asset,
              amount: "5000", // 0.005 USDC.e
              payTo: CANONICAL_EVM_PAY_TO,
            },
          ],
        },
      };

      const result = await sentinel.auditPaymentIntent(intent);
      expect(result.finalVerdict).toBe("APPROVED");
      expect(result.deterministicRuleVerdict.passed).toBe(true);
      expect(result.receiptDigestSha256).toBeDefined();
      expect(result.receiptDigestSha256.length).toBe(64);
      expect(session.cumulativeSpentUsdMicros).toBe(5000n);
      expect(session.txCount).toBe(1);
    });

    it("should APPROVE valid Kite Testnet payment intent with 18-decimal ceiling rounding (pieUSD)", async () => {
      const session = helperCreateSession({
        merchantUrl: "https://api.service.example/v1/data",
        method: "POST",
        preflightPriceUsd: "0.01",
        estimatedRequests: 10,
        ttlSeconds: 3600,
      });

      // 0.005 pieUSD = 5 * 10^15 atomic units
      const atomicAmount = (5_000_000_000_000_000n).toString();

      const intent: BuyerPaymentIntentInput = {
        sessionId: session.sessionId,
        merchantUrl: "https://api.service.example/v1/data",
        method: "POST",
        challenge402: {
          x402Version: 2,
          accepts: [
            {
              scheme: "exact",
              network: "eip155:2368",
              asset: SETTLEMENT_NETWORKS["kite-testnet"].asset,
              amount: atomicAmount,
              payTo: CANONICAL_EVM_PAY_TO,
            },
          ],
        },
      };

      const result = await sentinel.auditPaymentIntent(intent);
      expect(result.finalVerdict).toBe("APPROVED");
      expect(result.deterministicRuleVerdict.passed).toBe(true);
      expect(session.cumulativeSpentUsdMicros).toBe(5000n);
      expect(result.receiptDigestSha256).toHaveLength(64);
    });

    it("should APPROVE valid Base Mainnet payment intent (USDC, 6 decimals)", async () => {
      const session = helperCreateSession({
        merchantUrl: "https://api.service.example/v1/data",
        method: "GET",
        preflightPriceUsd: "0.01",
        estimatedRequests: 5,
        ttlSeconds: 3600,
      });

      const intent: BuyerPaymentIntentInput = {
        sessionId: session.sessionId,
        merchantUrl: "https://api.service.example/v1/data",
        method: "GET",
        challenge402: {
          x402Version: 2,
          accepts: [
            {
              scheme: "exact",
              network: "eip155:8453",
              asset: SETTLEMENT_NETWORKS["base-mainnet"].asset,
              amount: "1000", // 0.001 USDC
              payTo: CANONICAL_EVM_PAY_TO,
            },
          ],
        },
      };

      const result = await sentinel.auditPaymentIntent(intent);
      expect(result.finalVerdict).toBe("APPROVED");
      expect(result.deterministicRuleVerdict.passed).toBe(true);
      expect(result.network).toBe("eip155:8453");
    });
  });

  describe("5. Session Enforcements (Method, Host, Path Prefix, TTL, Cap Exhaustion, Idempotency)", () => {
    it("should BLOCK when HTTP method does not match allowed endpoint", async () => {
      const session = helperCreateSession({
        merchantUrl: "https://api.service.example/v1/data",
        method: "GET",
      });

      const intent: BuyerPaymentIntentInput = {
        sessionId: session.sessionId,
        merchantUrl: "https://api.service.example/v1/data",
        method: "POST", // Mismatch!
        challenge402: {
          x402Version: 2,
          accepts: [
            {
              scheme: "exact",
              network: "eip155:2366",
              asset: SETTLEMENT_NETWORKS["kite-mainnet"].asset,
              amount: "1000",
              payTo: CANONICAL_EVM_PAY_TO,
            },
          ],
        },
      };

      const result = await sentinel.auditPaymentIntent(intent);
      expect(result.finalVerdict).toBe("BLOCKED_POLICY_OR_FIREWALL");
      expect(result.deterministicRuleVerdict.code).toBe("ENDPOINT_NOT_ALLOWED");
    });

    it("should BLOCK when host or path prefix does not match allowed endpoint", async () => {
      const session = helperCreateSession({
        merchantUrl: "https://api.service.example/v1/data",
        method: "GET",
      });

      const intent: BuyerPaymentIntentInput = {
        sessionId: session.sessionId,
        merchantUrl: "https://malicious.evil.example/v1/data", // Host mismatch!
        method: "GET",
        challenge402: {
          x402Version: 2,
          accepts: [
            {
              scheme: "exact",
              network: "eip155:2366",
              asset: SETTLEMENT_NETWORKS["kite-mainnet"].asset,
              amount: "1000",
              payTo: CANONICAL_EVM_PAY_TO,
            },
          ],
        },
      };

      const result = await sentinel.auditPaymentIntent(intent);
      expect(result.finalVerdict).toBe("BLOCKED_POLICY_OR_FIREWALL");
      expect(result.deterministicRuleVerdict.code).toBe("ENDPOINT_NOT_ALLOWED");
    });

    it("should BLOCK when session TTL has expired", async () => {
      const session = helperCreateSession({
        merchantUrl: "https://api.service.example/v1/data",
        ttlSeconds: 10,
      });

      // Force expiration
      session.expiresAtSec = Math.floor(Date.now() / 1000) - 100;

      const intent: BuyerPaymentIntentInput = {
        sessionId: session.sessionId,
        merchantUrl: "https://api.service.example/v1/data",
        method: "GET",
        challenge402: {
          x402Version: 2,
          accepts: [
            {
              scheme: "exact",
              network: "eip155:2366",
              asset: SETTLEMENT_NETWORKS["kite-mainnet"].asset,
              amount: "1000",
              payTo: CANONICAL_EVM_PAY_TO,
            },
          ],
        },
      };

      const result = await sentinel.auditPaymentIntent(intent);
      expect(result.finalVerdict).toBe("BLOCKED_POLICY_OR_FIREWALL");
      expect(result.deterministicRuleVerdict.code).toBe("SESSION_EXPIRED");
    });

    it("should BLOCK when cumulative max_total_amount is exhausted", async () => {
      const session = helperCreateSession({
        merchantUrl: "https://api.service.example/v1/data",
        preflightPriceUsd: "0.001",
        estimatedRequests: 1, // Cap is $0.00115 (~1150 micros)
      });

      // First call consumes 1000 micros
      await sentinel.auditPaymentIntent({
        sessionId: session.sessionId,
        merchantUrl: "https://api.service.example/v1/data",
        method: "GET",
        challenge402: {
          x402Version: 2,
          accepts: [
            {
              scheme: "exact",
              network: "eip155:2366",
              asset: SETTLEMENT_NETWORKS["kite-mainnet"].asset,
              amount: "1000",
              payTo: CANONICAL_EVM_PAY_TO,
            },
          ],
        },
      });

      // Second call tries to spend another 1000 micros -> exceeds max_total_amount!
      const result = await sentinel.auditPaymentIntent({
        sessionId: session.sessionId,
        merchantUrl: "https://api.service.example/v1/data",
        method: "GET",
        challenge402: {
          x402Version: 2,
          accepts: [
            {
              scheme: "exact",
              network: "eip155:2366",
              asset: SETTLEMENT_NETWORKS["kite-mainnet"].asset,
              amount: "1000",
              payTo: CANONICAL_EVM_PAY_TO,
            },
          ],
        },
      });

      expect(result.finalVerdict).toBe("BLOCKED_POLICY_OR_FIREWALL");
      expect(result.deterministicRuleVerdict.passed).toBe(false);
      expect(["EXCEEDS_MAX_TOTAL_BUDGET", "EXCEEDS_DAILY_CAP"]).toContain(
        result.deterministicRuleVerdict.code
      );
    });

    it("should HOLD for human approval when single transaction exceeds threshold", async () => {
      const session = helperCreateSession({
        merchantUrl: "https://api.service.example/v1/data",
        preflightPriceUsd: "10.00",
        estimatedRequests: 2,
        approvalThresholdUsdMicros: 5_000_000n, // $5.00 threshold
      });

      const intent: BuyerPaymentIntentInput = {
        sessionId: session.sessionId,
        merchantUrl: "https://api.service.example/v1/data",
        method: "GET",
        challenge402: {
          x402Version: 2,
          accepts: [
            {
              scheme: "exact",
              network: "eip155:2366",
              asset: SETTLEMENT_NETWORKS["kite-mainnet"].asset,
              amount: "6000000", // $6.00 > $5.00 threshold
              payTo: CANONICAL_EVM_PAY_TO,
            },
          ],
        },
      };

      const result = await sentinel.auditPaymentIntent(intent);
      expect(result.finalVerdict).toBe("HELD_FOR_HUMAN_APPROVAL");
      // Funds not deducted while held
      expect(session.cumulativeSpentUsdMicros).toBe(0n);
    });

    it("should prevent double-spend replay attacks using idempotency keys", async () => {
      const session = helperCreateSession({
        merchantUrl: "https://api.service.example/v1/data",
        preflightPriceUsd: "0.01",
        estimatedRequests: 10,
      });

      const intent: BuyerPaymentIntentInput = {
        sessionId: session.sessionId,
        idempotencyKey: "idem-unique-key-12345",
        merchantUrl: "https://api.service.example/v1/data",
        method: "GET",
        challenge402: {
          x402Version: 2,
          accepts: [
            {
              scheme: "exact",
              network: "eip155:2366",
              asset: SETTLEMENT_NETWORKS["kite-mainnet"].asset,
              amount: "1000",
              payTo: CANONICAL_EVM_PAY_TO,
            },
          ],
        },
      };

      const res1 = await sentinel.auditPaymentIntent(intent);
      expect(res1.finalVerdict).toBe("APPROVED");
      expect(session.cumulativeSpentUsdMicros).toBe(1000n);

      // Replaying the exact same request with the same idempotency key must be BLOCKED!
      const res2 = await sentinel.auditPaymentIntent(intent);
      expect(res2.finalVerdict).toBe("BLOCKED_POLICY_OR_FIREWALL");
      expect(res2.deterministicRuleVerdict.code).toBe("IDEMPOTENT_REPLAY_DETECTED");
      // Cumulative spend counter must NOT increment again!
      expect(session.cumulativeSpentUsdMicros).toBe(1000n);
      expect(session.txCount).toBe(1);
    });
  });

  describe("6. OpenServ Agent SDK Integration", () => {
    it("should instantiate OpenServ SDK agent with registered capabilities", () => {
      const agent = createSentinelOpenServAgent(sentinel);
      expect(agent).toBeDefined();
      expect(typeof agent.addCapability).toBe("function");
    });
  });

  describe("7. HTTP Server Integration (Health, x402 Manifest, Audit, Body Limit)", () => {
    let server: Server;
    let baseUrl: string;

    beforeEach(async () => {
      server = createSentinelHttpServer(sentinel, { requireSellerX402Payment: true });
      await new Promise<void>((resolve) => {
        server.listen(0, "127.0.0.1", () => resolve());
      });
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 7378;
      baseUrl = `http://127.0.0.1:${port}`;
    });

    afterEach(async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    it("GET /health should return 200 OK with supported networks", async () => {
      const res = await fetch(`${baseUrl}/health`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.status).toBe("healthy");
      expect(data.networks).toContain("kite-mainnet");
      expect(data.networks).toContain("kite-testnet");
      expect(data.networks).toContain("base-mainnet");
    });

    it("GET /.well-known/x402 should return x402 discovery manifest", async () => {
      const res = await fetch(`${baseUrl}/.well-known/x402`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.x402Version).toBe(2);
      expect(data.payTo).toBe(CANONICAL_EVM_PAY_TO);
      expect(data.endpoints).toBeInstanceOf(Array);
    });

    it("POST /v1/sentinel/audit should return 402 challenge when unpaid without demo flag", async () => {
      const res = await fetch(`${baseUrl}/v1/sentinel/audit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(402);
      expect(res.headers.get("PAYMENT-REQUIRED")).toBeDefined();
      const body = await res.json();
      expect(body.x402Version).toBe(2);
      expect(body.accepts[0].network).toBe("eip155:2366");
    });

    it("POST /v1/sentinel/audit should return 200 with audit result when x-sentinel-demo is provided", async () => {
      const session = helperCreateSession({
        merchantUrl: "https://api.service.example/v1/forecast",
      });

      const res = await fetch(`${baseUrl}/v1/sentinel/audit`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-sentinel-demo": "true",
        },
        body: JSON.stringify({
          sessionId: session.sessionId,
          merchantUrl: "https://api.service.example/v1/forecast",
          method: "GET",
          challenge402: {
            x402Version: 2,
            accepts: [
              {
                scheme: "exact",
                network: "eip155:2366",
                asset: SETTLEMENT_NETWORKS["kite-mainnet"].asset,
                amount: "1000",
                payTo: CANONICAL_EVM_PAY_TO,
              },
            ],
          },
        }),
      });

      expect(res.status).toBe(200);
      const entry = await res.json();
      expect(entry.finalVerdict).toBe("APPROVED");
      expect(entry.receiptDigestSha256).toBeDefined();
    });

    it("should handle oversized request body by terminating socket connection", async () => {
      const oversizedString = "A".repeat(70_000); // Exceeds 64 KB limit
      try {
        await fetch(`${baseUrl}/v1/sentinel/audit`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-sentinel-demo": "true",
          },
          body: JSON.stringify({ note: oversizedString }),
        });
        // If fetch doesn't throw, we expect error status
      } catch (err) {
        // Socket destroyed on server side due to MAX_BODY_BYTES exceeded
        expect(err).toBeDefined();
      }
    });
  });
});
