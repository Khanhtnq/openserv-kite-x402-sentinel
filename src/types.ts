import { z } from "zod";

// ============================================================================
// 1. Kite Agent Passport Exact Delegation Schema
//    (Matches gokite-ai/passport-skills/form-session-delegation/references/delegation-schema.md)
// ============================================================================

export const KiteAllowedEndpointSchema = z
  .object({
    method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]),
    host: z.string().min(1),
    path_prefix: z.string().startsWith("/"),
  })
  .strict();

export type KiteAllowedEndpoint = z.infer<typeof KiteAllowedEndpointSchema>;

export const KiteExecutionConstraintsSchema = z
  .object({
    x402: z
      .object({
        scope_mode: z.literal("scoped"),
        allowed_endpoints: z.array(KiteAllowedEndpointSchema).min(1),
      })
      .strict()
      .optional(),
  })
  .strict();

export const KitePaymentPolicySchema = z
  .object({
    max_amount_per_tx: z.string().regex(/^(?:0|[1-9]\d*)(?:\.\d{1,6})?$/),
    max_total_amount: z
      .string()
      .regex(/^(?:0|[1-9]\d*)(?:\.\d{1,6})?$/)
      .optional(),
    ttl_seconds: z.number().int().positive(),
    currency: z.literal("USD").optional(),
  })
  .strict();

export const KiteDelegationSchema = z
  .object({
    task: z
      .object({
        summary: z.string().min(3).max(160),
      })
      .strict(),
    payment_policy: KitePaymentPolicySchema,
    execution_constraints: KiteExecutionConstraintsSchema.optional(),
    routing_enabled: z.boolean().optional(),
    routing_cost_cap_usd_micros: z.number().int().min(0).optional(),
  })
  .strict();

export type KiteDelegation = z.infer<typeof KiteDelegationSchema>;

export interface SignedKiteSessionMandate {
  sessionId: string;
  userRootAddress: `0x${string}`;
  agentDelegatedAddress: `0x${string}`;
  ephemeralSessionAddress: `0x${string}`;
  delegation: KiteDelegation;
  issuedAtSec: number;
  expiresAtSec: number;
  approvalThresholdUsdMicros: bigint;
  dailyCapUsdMicros: bigint;
  signature: `0x${string}`;
}

export interface IdempotencyRecord {
  key: string;
  requestFingerprint: string;
  status: "in_flight" | "settled" | "merchant_failed_held" | "rejected";
  amountUsdMicros: string;
  responseSnapshot?: unknown;
  updatedAtIso: string;
}

export interface KiteSessionRuntimeState {
  sessionId: string;
  userRootAddress: `0x${string}`;
  agentDelegatedAddress: `0x${string}`;
  ephemeralSessionAddress: `0x${string}`;
  delegation: KiteDelegation;
  issuedAtSec: number;
  expiresAtSec: number;
  approvalThresholdUsdMicros: bigint;
  dailyCapUsdMicros: bigint;
  cumulativeSpentUsdMicros: bigint;
  dailySpentUsdMicros: bigint;
  txCount: number;
  lockedNetwork: string | null;
  lockedAsset: `0x${string}` | null;
  mandateSignature?: `0x${string}`;
  idempotency: Map<string, IdempotencyRecord>;
}

// ============================================================================
// 2. x402 v2 Challenge & Buyer Intent Types
// ============================================================================

export interface X402AcceptOption {
  scheme: string;
  network: string;
  asset: string;
  amount?: string;
  maxAmountRequired?: string;
  payTo: string;
  maxTimeoutSeconds?: number;
  resource?: string;
  description?: string;
  mimeType?: string;
  extra?: {
    name?: string;
    version?: string;
    [k: string]: unknown;
  } | null;
}

export interface X402ChallengePayload {
  x402Version: number;
  accepts: X402AcceptOption[];
  error?: string;
  description?: string;
}

export interface BuyerPaymentIntentInput {
  sessionId?: string;
  taskDescription?: string;
  merchantUrl: string;
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  advertisedPriceUsd?: string;
  merchantUntrustedNote?: string;
  idempotencyKey?: string;
  challenge402: X402ChallengePayload;
  evmTxOptional?: SimulateEvmTxInput;
  eip712Optional?: InspectEip712Input;
  /**
   * Used in adversarial tests & workbench presets to prove that even if an
   * upstream/rogue LLM proposes APPROVE or an inflated spend multiplier,
   * Sentinel's deterministic policy clamps and blocks the violation.
   */
  simulateRogueModelProposal?: {
    proposedAction: "APPROVE" | "HOLD_FOR_APPROVAL" | "REJECT_RISK" | "REJECT_VALUE";
    proposedAmountMultiplier?: number;
    explanation?: string;
  };
}

// ============================================================================
// 3. EVM Calldata, EIP-7702 & EIP-712 Firewall Types
// ============================================================================

export interface Eip7702AuthorizationItem {
  chainId: number;
  address: string;
  nonce?: number;
}

export interface SimulateEvmTxInput {
  chainId: number | string;
  from: string;
  to: string | null;
  data?: string;
  value?: string;
  gas?: string;
  authorizationList?: Eip7702AuthorizationItem[];
  trustedSpenders?: string[];
  runLiveRpcEthCall?: boolean;
}

export interface DecodedCallSummary {
  selector: string;
  signature: string;
  category:
    | "READ_ONLY"
    | "ERC20_APPROVAL"
    | "ERC20_TRANSFER"
    | "PERMIT2"
    | "NFT_APPROVAL_ALL"
    | "MULTICALL"
    | "NATIVE_TRANSFER"
    | "CONTRACT_CREATION"
    | "UNKNOWN_CALL";
  spenderOrRecipient?: string;
  amountAtomic?: string;
  isUnlimitedApproval: boolean;
}

export interface EvmFirewallReport {
  verdict: "ALLOW" | "HOLD" | "BLOCK";
  riskScore: number;
  riskTier: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  chainId: number;
  networkName: string;
  decodedCall: DecodedCallSummary;
  reasons: string[];
  rpcSimulation: {
    attempted: boolean;
    rpcUrl?: string;
    chainIdVerified?: number;
    ethCallSuccess?: boolean;
    returnDataOrError?: string;
    latencyMs?: number;
  };
}

export interface InspectEip712Input {
  domain: {
    name?: string;
    version?: string;
    chainId?: number | string;
    verifyingContract?: string;
  };
  primaryType: string;
  types?: Record<string, Array<{ name: string; type: string }>>;
  message: Record<string, unknown>;
  expectedPayTo?: string;
  maxAllowedAtomic?: string;
}

export interface Eip712FirewallReport {
  verdict: "ALLOW" | "HOLD" | "BLOCK";
  riskScore: number;
  primaryType: string;
  reasons: string[];
}

// ============================================================================
// 4. OpenServ SERV Reasoning Proposal & Dual-Authority Audit Ledger
// ============================================================================

export const ServDecisionProposalSchema = z
  .object({
    proposedAction: z.enum([
      "APPROVE",
      "HOLD_FOR_APPROVAL",
      "REJECT_RISK",
      "REJECT_VALUE",
    ]),
    proposedBudgetMultiplier: z.number().min(0).max(10),
    valueScore: z.number().int().min(0).max(100),
    promptInjectionDetected: z.boolean(),
    citedMerchantFields: z.array(z.string()),
    explanation: z.string().min(1),
  })
  .strict();

export type ServDecisionProposal = z.infer<typeof ServDecisionProposalSchema>;

export interface PromptInjectionScanResult {
  flagged: boolean;
  triggers: string[];
  sanitizedExcerpt: string;
}

export interface ServReasoningTrace {
  mode: "live_serv_reasoning" | "deterministic_fallback" | "prompt_guard_quarantined" | "rogue_model_simulation";
  endpoint: string;
  model: string;
  systemPromptVersion: string;
  servToolsDeclared: Array<"serv_prompt_guard" | "serv_shadow_agent">;
  kronosEnabled: false;
  multipathEnabled: boolean;
  precheckInjection: PromptInjectionScanResult;
  rawProposal: ServDecisionProposal | null;
  clampedBudgetMultiplier: number;
  refusalOrShortReplyDropped: boolean;
  latencyMs: number;
  tokenUsage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
}

export type FinalSentinelVerdict =
  | "APPROVED"
  | "HELD_FOR_HUMAN_APPROVAL"
  | "BLOCKED_PROMPT_INJECTION"
  | "BLOCKED_POLICY_OR_FIREWALL";

export interface AuditLedgerEntry {
  entryId: string;
  timestampIso: string;
  sessionId: string;
  idempotencyKey: string;
  merchantUrl: string;
  method: string;
  network: string;
  asset: string;
  symbol: string;
  requestedAmountAtomic: string;
  requestedAmountUsd: string;
  payTo: string;
  finalVerdict: FinalSentinelVerdict;
  /**
   * Kept strictly separate from `servReasoningExplanation` (Edition 01 Ledgerly pattern):
   * `deterministicRuleVerdict` is the binding code enforcement fact;
   * `servReasoningExplanation` is bounded AI commentary and value judgment.
   */
  deterministicRuleVerdict: {
    passed: boolean;
    code: string;
    summary: string;
    checks: Array<{
      check: string;
      passed: boolean;
      detail: string;
    }>;
  };
  servReasoningExplanation: string;
  servTrace: ServReasoningTrace;
  evmFirewall?: EvmFirewallReport;
  eip712Firewall?: Eip712FirewallReport;
  signedPaymentHeaderPreview?: string;
  kpassCliCommand?: string;
  explorerUrl: string;
  receiptDigestSha256: string;
}

export interface SentinelConfig {
  payTo: `0x${string}`;
  kiteNetwork: "mainnet" | "testnet";
  sellerPriceUsd: string;
  facilitatorUrl: string;
  baseFacilitatorUrl: string;
  servApiKey?: string;
  servBaseUrl: string;
  servModel: string;
  port: number;
  allowLocalhostMerchantUrls?: boolean;
}
