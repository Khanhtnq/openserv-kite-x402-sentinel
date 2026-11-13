import { Agent } from "@openserv-labs/sdk";
import { z } from "zod";
import { KitePaymentSentinel } from "./sentinel.js";
import { simulateEvmTransaction, inspectEip712TypedData } from "./firewall.js";
import { compileKiteDelegation } from "./kitePassport.js";

const SYSTEM_PROMPT = `You are the OpenServ Kite x402 Sentinel Agent.
Your duty is to act as an autonomous, dual-authority payment guardian protecting AI agents from malicious x402 traps,
prompt injections, bait-and-switch pricing, and dangerous EVM calldata / EIP-7702 delegation hijacks.
Always evaluate payment safety through deterministic spend policies and SERV Reasoning.`;

/**
 * Creates an OpenServ SDK Agent instance registered with Sentinel capabilities:
 * 1. audit_kite_x402_payment
 * 2. simulate_evm_firewall
 * 3. inspect_eip712_signature
 * 4. compile_kite_delegation
 * 5. get_sentinel_audit_ledger
 *
 * Can be instantiated offline during test runs using placeholder keys.
 * Never initiates network tunnels unless agent.start() is explicitly invoked.
 */
export function createSentinelOpenServAgent(
  sentinel?: KitePaymentSentinel,
  options?: { apiKey?: string; authToken?: string }
): Agent {
  const sentinelInstance = sentinel || new KitePaymentSentinel();

  const apiKey =
    options?.apiKey ||
    process.env.OPENSERV_API_KEY ||
    "openserv_offline_placeholder_key";

  const authToken =
    options?.authToken ||
    process.env.OPENSERV_AUTH_TOKEN ||
    "auth_token_placeholder";

  const agent = new Agent({
    systemPrompt: SYSTEM_PROMPT,
    apiKey,
    authToken,
    port: sentinelInstance.getConfig().port,
  });

  // 1. Audit Kite x402 Payment Intent Capability
  agent.addCapability({
    name: "audit_kite_x402_payment",
    description:
      "Performs a comprehensive dual-authority audit of a proposed Kite x402 v2 payment intent against delegation policies, SSRF bounds, and SERV Reasoning Prompt Guard.",
    inputSchema: z.object({
      merchantUrl: z.string().describe("Target merchant URL"),
      method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).optional().default("GET"),
      advertisedPriceUsd: z.string().optional().describe("Pre-advertised price in USD decimal format"),
      merchantUntrustedNote: z.string().optional().describe("Untrusted memo or header string from merchant"),
      challenge402: z.any().describe("Raw x402 challenge payload returned by merchant with status 402"),
      sessionId: z.string().optional().describe("Kite session ID to audit against"),
      idempotencyKey: z.string().optional().describe("Unique idempotency key for replay prevention"),
    }),
    async run({ args }) {
      const entry = await sentinelInstance.auditPaymentIntent({
        merchantUrl: args.merchantUrl,
        method: args.method,
        advertisedPriceUsd: args.advertisedPriceUsd,
        merchantUntrustedNote: args.merchantUntrustedNote,
        challenge402: args.challenge402,
        sessionId: args.sessionId,
        idempotencyKey: args.idempotencyKey,
      });
      return JSON.stringify(entry);
    },
  });

  // 2. Simulate EVM Calldata & EIP-7702 Firewall
  agent.addCapability({
    name: "simulate_evm_firewall",
    description:
      "Simulates EVM transaction calldata, checks for unlimited approvals, EIP-7702 EOA delegation hijacks, and contract creation risks.",
    inputSchema: z.object({
      chainId: z.union([z.number(), z.string()]).describe("EVM chain ID (2366, 2368, 8453)"),
      from: z.string().describe("Sender address"),
      to: z.string().nullable().describe("Target contract address or null for contract creation"),
      data: z.string().optional().describe("Transaction hex calldata"),
      value: z.string().optional().describe("Native value in wei"),
      authorizationList: z
        .array(
          z.object({
            chainId: z.number(),
            address: z.string(),
            nonce: z.number().optional(),
          })
        )
        .optional()
        .describe("EIP-7702 authorization list"),
      trustedSpenders: z.array(z.string()).optional().describe("List of trusted spender addresses"),
      runLiveRpcEthCall: z.boolean().optional().describe("Whether to run live RPC eth_call simulation"),
    }),
    async run({ args }) {
      const report = await simulateEvmTransaction({
        chainId: args.chainId,
        from: args.from,
        to: args.to,
        data: args.data,
        value: args.value,
        authorizationList: args.authorizationList,
        trustedSpenders: args.trustedSpenders,
        runLiveRpcEthCall: args.runLiveRpcEthCall,
      });
      return JSON.stringify(report);
    },
  });

  // 3. Inspect EIP-712 Typed Data Signature
  agent.addCapability({
    name: "inspect_eip712_signature",
    description:
      "Inspects EIP-712 typed data messages (EIP-3009, Permit, Permit2) to prevent unauthorized drain attacks.",
    inputSchema: z.object({
      primaryType: z.string().describe("EIP-712 primary type (e.g. TransferWithAuthorization, Permit, PermitSingle)"),
      domain: z.object({
        name: z.string().optional(),
        version: z.string().optional(),
        chainId: z.union([z.number(), z.string()]).optional(),
        verifyingContract: z.string().optional(),
      }),
      message: z.record(z.unknown()).describe("EIP-712 message payload"),
      expectedPayTo: z.string().optional().describe("Expected recipient address"),
      maxAllowedAtomic: z.string().optional().describe("Maximum allowed atomic token amount"),
    }),
    async run({ args }) {
      const report = inspectEip712TypedData({
        primaryType: args.primaryType,
        domain: args.domain,
        message: args.message,
        expectedPayTo: args.expectedPayTo,
        maxAllowedAtomic: args.maxAllowedAtomic,
      });
      return JSON.stringify(report);
    },
  });

  // 4. Compile Kite Agent Passport Delegation
  agent.addCapability({
    name: "compile_kite_delegation",
    description:
      "Compiles and validates a strict Kite Agent Passport session delegation JSON and generates a shell-safe kpass CLI command.",
    inputSchema: z.object({
      taskSummary: z.string().min(3).max(160).describe("Human-readable task summary"),
      merchantUrl: z.string().describe("Target merchant URL for scoped execution"),
      method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).optional().default("GET"),
      preflightPriceUsd: z.string().describe("Advertised preflight price in USD"),
      estimatedRequests: z.number().int().positive().describe("Expected number of calls"),
      ttlSeconds: z.number().int().positive().describe("Session validity window in seconds"),
      safetyBufferBps: z.number().int().optional().default(1500).describe("Safety buffer in basis points (default 1500 = 15%)"),
    }),
    async run({ args }) {
      const compiled = compileKiteDelegation({
        taskSummary: args.taskSummary,
        merchantUrl: args.merchantUrl,
        method: args.method,
        preflightPriceUsd: args.preflightPriceUsd,
        estimatedRequests: args.estimatedRequests,
        ttlSeconds: args.ttlSeconds,
        safetyBufferBps: args.safetyBufferBps,
      });
      return JSON.stringify(compiled);
    },
  });

  // 5. Get Sentinel Audit Ledger
  agent.addCapability({
    name: "get_sentinel_audit_ledger",
    description: "Retrieves the immutable audit ledger entries recording all processed payments, verdicts, and SERV traces.",
    inputSchema: z.object({
      limit: z.number().int().optional().default(50),
    }),
    async run({ args }) {
      const ledger = sentinelInstance.getLedger().slice(-args.limit);
      return JSON.stringify({ count: ledger.length, entries: ledger });
    },
  });

  return agent;
}
