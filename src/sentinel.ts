import { createHash } from "node:crypto";
import {
  AuditLedgerEntry,
  BuyerPaymentIntentInput,
  FinalSentinelVerdict,
  IdempotencyRecord,
  KiteSessionRuntimeState,
  SentinelConfig,
  X402AcceptOption,
} from "./types.js";
import {
  CANONICAL_EVM_PAY_TO,
  DEFAULT_SELLER_PRICE_USD,
  resolveSettlementNetwork,
  SERV_DEFAULT_MODEL,
  SERV_REASONING_BASE_URL,
  SETTLEMENT_NETWORKS,
} from "./constants.js";
import {
  atomicToUsdMicros,
  compileKiteDelegation,
  createSessionRuntimeState,
  formatMicrosToUsd,
  parseUsdToMicros,
  validateMerchantUrlSafety,
} from "./kitePassport.js";
import { inspectEip712TypedData, simulateEvmTransaction } from "./firewall.js";
import { evaluateWithServReasoning } from "./servReasoning.js";

/**
 * Loads Sentinel configuration from environment variables with sensible defaults.
 */
export function loadSentinelConfig(overrides?: Partial<SentinelConfig>): SentinelConfig {
  const envPayTo = process.env.SENTINEL_PAY_TO || process.env.PAY_TO;
  const payTo = (
    envPayTo && envPayTo.startsWith("0x")
      ? (envPayTo as `0x${string}`)
      : CANONICAL_EVM_PAY_TO
  ) as `0x${string}`;

  const kiteNet = (process.env.KITE_NETWORK === "testnet" ? "testnet" : "mainnet") as
    | "mainnet"
    | "testnet";

  const sellerPrice =
    process.env.PRICE_USD ||
    process.env.SELLER_PRICE_USD ||
    DEFAULT_SELLER_PRICE_USD;
  const facilitatorUrl =
    process.env.FACILITATOR_URL || SETTLEMENT_NETWORKS["kite-mainnet"].defaultFacilitatorUrl;
  const baseFacilitatorUrl =
    process.env.BASE_FACILITATOR_URL || SETTLEMENT_NETWORKS["base-mainnet"].defaultFacilitatorUrl;

  const servApiKey = process.env.OPENSERV_API_KEY || process.env.SERV_API_KEY;
  const servBaseUrl = process.env.SERV_BASE_URL || SERV_REASONING_BASE_URL;
  const servModel = process.env.SERV_MODEL || SERV_DEFAULT_MODEL;

  const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 8080;
  const allowLocalhost = process.env.ALLOW_LOCALHOST === "true";

  return {
    payTo,
    kiteNetwork: kiteNet,
    sellerPriceUsd: sellerPrice,
    facilitatorUrl,
    baseFacilitatorUrl,
    servApiKey,
    servBaseUrl,
    servModel,
    port,
    allowLocalhostMerchantUrls: allowLocalhost,
    ...overrides,
  };
}

export class KitePaymentSentinel {
  private config: SentinelConfig;
  private sessions: Map<string, KiteSessionRuntimeState> = new Map();
  private auditLedger: AuditLedgerEntry[] = [];

  constructor(configOverrides?: Partial<SentinelConfig>) {
    this.config = loadSentinelConfig(configOverrides);
  }

  public getConfig(): SentinelConfig {
    return { ...this.config };
  }

  public registerSession(state: KiteSessionRuntimeState): KiteSessionRuntimeState {
    this.sessions.set(state.sessionId, state);
    return state;
  }

  public createDefaultSession(
    overrides?: Partial<Parameters<typeof createSessionRuntimeState>[0]>
  ): KiteSessionRuntimeState {
    const defaultCompiled = compileKiteDelegation({
      taskSummary: "Default autonomous Kite session",
      merchantUrl: "https://api.weather-kite.example/v1/forecast",
      method: "GET",
      preflightPriceUsd: "0.01",
      estimatedRequests: 100,
      ttlSeconds: 86400,
      allowLocalhostMerchantUrls: true,
    });

    const session = createSessionRuntimeState({
      userRootAddress: "0x1111111111111111111111111111111111111111",
      agentDelegatedAddress: "0x2222222222222222222222222222222222222222",
      ephemeralSessionAddress: "0x3333333333333333333333333333333333333333",
      delegation: defaultCompiled.delegation,
      approvalThresholdUsdMicros: 5_000_000n, // $5.00
      dailyCapUsdMicros: 10_000_000n, // $10.00
      ...overrides,
    });

    return this.registerSession(session);
  }

  public getSession(sessionId: string): KiteSessionRuntimeState | undefined {
    return this.sessions.get(sessionId);
  }

  public getLedger(): AuditLedgerEntry[] {
    return [...this.auditLedger];
  }

  /**
   * Dual-Authority audit engine:
   * First applies strict deterministic policy checks (SSRF, session TTL, spend limits,
   * asset pinning, EIP-7702, EVM & EIP-712 firewalls, replay table).
   * Then executes SERV Reasoning (serv_prompt_guard + serv_shadow_agent).
   * Rogue-Model Clamp: AI reasoning can veto or hold, but can NEVER approve an out-of-policy
   * or adversarial payment!
   */
  public async auditPaymentIntent(
    intent: BuyerPaymentIntentInput,
    nowSec?: number
  ): Promise<AuditLedgerEntry> {
    const timestamp = nowSec ?? Math.floor(Date.now() / 1000);
    const timestampIso = new Date(timestamp * 1000).toISOString();
    const entryId = `audit-${Math.random().toString(36).substring(2, 10)}-${Date.now().toString(36)}`;
    const idempotencyKey = intent.idempotencyKey || `idem-${entryId}`;

    const checks: Array<{ check: string; passed: boolean; detail: string }> = [];
    let deterministicPassed = true;
    let blockReasonCode = "OK";
    let blockSummary = "All deterministic policy and safety checks passed.";

    // 1. SSRF & URL Validation
    const urlCheck = validateMerchantUrlSafety(
      intent.merchantUrl,
      this.config.allowLocalhostMerchantUrls ?? false
    );
    if (!urlCheck.ok || !urlCheck.host || !urlCheck.pathname) {
      deterministicPassed = false;
      blockReasonCode = "SSRF_OR_INVALID_URL";
      blockSummary = `SSRF check failed: ${urlCheck.reason}`;
      checks.push({ check: "SSRF_URL_VALIDATION", passed: false, detail: blockSummary });
    } else {
      checks.push({
        check: "SSRF_URL_VALIDATION",
        passed: true,
        detail: `Safe destination: ${urlCheck.normalizedUrl}`,
      });
    }

    // 2. Session Lookup or Default Fallback
    let session: KiteSessionRuntimeState | undefined;
    if (intent.sessionId) {
      session = this.getSession(intent.sessionId);
      if (!session) {
        deterministicPassed = false;
        blockReasonCode = "SESSION_NOT_FOUND";
        blockSummary = `Specified sessionId "${intent.sessionId}" not registered in Sentinel`;
        checks.push({ check: "SESSION_LOOKUP", passed: false, detail: blockSummary });
      }
    } else {
      // Create an ephemeral session matching the intent task
      session = this.createDefaultSession();
    }

    // 3. Session Expiry & Constraints Check
    if (session) {
      if (timestamp >= session.expiresAtSec) {
        deterministicPassed = false;
        blockReasonCode = "SESSION_EXPIRED";
        blockSummary = `Session ${session.sessionId} expired at ${session.expiresAtSec} (now=${timestamp})`;
        checks.push({ check: "SESSION_TTL", passed: false, detail: blockSummary });
      } else {
        checks.push({
          check: "SESSION_TTL",
          passed: true,
          detail: `Active until ${session.expiresAtSec} (${session.expiresAtSec - timestamp}s remaining)`,
        });
      }

      // Check Allowed Endpoints if execution_constraints are set
      const executionConstraints = session.delegation.execution_constraints?.x402;
      if (executionConstraints && executionConstraints.allowed_endpoints) {
        const reqMethod = (intent.method || "GET").toUpperCase();
        const reqHost = urlCheck.host || "";
        const reqPath = urlCheck.pathname || "/";

        const matches = executionConstraints.allowed_endpoints.some((ep) => {
          const methodMatch = ep.method === reqMethod;
          const hostMatch = ep.host.toLowerCase() === reqHost.toLowerCase();
          const pathMatch = reqPath.startsWith(ep.path_prefix);
          return methodMatch && hostMatch && pathMatch;
        });

        if (!matches) {
          deterministicPassed = false;
          blockReasonCode = "ENDPOINT_NOT_ALLOWED";
          blockSummary = `Requested endpoint ${reqMethod} ${reqHost}${reqPath} is outside delegation allowed_endpoints`;
          checks.push({ check: "ALLOWED_ENDPOINTS", passed: false, detail: blockSummary });
        } else {
          checks.push({
            check: "ALLOWED_ENDPOINTS",
            passed: true,
            detail: `Endpoint matches scoped delegation constraints`,
          });
        }
      }
    }

    // 4. x402 Challenge Format Check
    if (
      !intent.challenge402 ||
      intent.challenge402.x402Version !== 2 ||
      !Array.isArray(intent.challenge402.accepts) ||
      intent.challenge402.accepts.length === 0
    ) {
      deterministicPassed = false;
      blockReasonCode = "INVALID_X402_CHALLENGE";
      blockSummary = "Challenge must be x402Version 2 with non-empty accepts array";
      checks.push({ check: "X402_SPEC_COMPLIANCE", passed: false, detail: blockSummary });
    } else {
      checks.push({
        check: "X402_SPEC_COMPLIANCE",
        passed: true,
        detail: `Valid x402 v2 challenge with ${intent.challenge402.accepts.length} option(s)`,
      });
    }

    // 5. Select Best Option & Resolve Settlement Network
    const options = intent.challenge402?.accepts || [];
    let selectedOption: X402AcceptOption | undefined = undefined;
    let netConfig: ReturnType<typeof resolveSettlementNetwork> = undefined;

    for (const opt of options) {
      if (opt.scheme !== "exact") continue;
      const resolved = resolveSettlementNetwork(opt.network);
      if (resolved) {
        selectedOption = opt;
        netConfig = resolved;
        break;
      }
    }

    if (!selectedOption || !netConfig) {
      deterministicPassed = false;
      blockReasonCode = "NO_SUPPORTED_NETWORK";
      blockSummary = "No supported settlement option matching exact scheme on Kite or Base";
      checks.push({ check: "NETWORK_RESOLUTION", passed: false, detail: blockSummary });
    } else {
      checks.push({
        check: "NETWORK_RESOLUTION",
        passed: true,
        detail: `Selected ${netConfig.displayName} (${netConfig.network}) for asset ${netConfig.symbol}`,
      });
    }

    // 6. Asset Verification & Session Pinning
    if (selectedOption && netConfig && session) {
      const optAsset = selectedOption.asset.toLowerCase();
      const canonicalAsset = netConfig.asset.toLowerCase();

      if (optAsset !== canonicalAsset) {
        deterministicPassed = false;
        blockReasonCode = "ASSET_MISMATCH";
        blockSummary = `Challenge asset ${optAsset} does not match canonical ${canonicalAsset} on ${netConfig.displayName}`;
        checks.push({ check: "CANONICAL_ASSET", passed: false, detail: blockSummary });
      } else {
        checks.push({
          check: "CANONICAL_ASSET",
          passed: true,
          detail: `Asset matches verified token contract ${netConfig.asset}`,
        });
      }

      // EIP-712 Domain Check
      if (
        (selectedOption.extra?.name && selectedOption.extra.name !== netConfig.eip712Domain.name) ||
        (selectedOption.extra?.version && selectedOption.extra.version !== netConfig.eip712Domain.version)
      ) {
        deterministicPassed = false;
        blockReasonCode = "EIP712_DOMAIN_MISMATCH";
        blockSummary = `Challenge EIP-712 extra domain (${selectedOption.extra?.name || ""} v${selectedOption.extra?.version || ""}) does not match expected (${netConfig.eip712Domain.name} v${netConfig.eip712Domain.version})`;
        checks.push({ check: "EIP712_DOMAIN_MATCH", passed: false, detail: blockSummary });
      } else {
        checks.push({
          check: "EIP712_DOMAIN_MATCH",
          passed: true,
          detail: "EIP-712 domain matches canonical network configuration",
        });
      }

      // Session network & asset pinning invariant (read-only; mutated on approval only)
      if (session.lockedNetwork && session.lockedNetwork !== netConfig.network) {
        deterministicPassed = false;
        blockReasonCode = "SESSION_NETWORK_MISMATCH";
        blockSummary = `Session is locked to network ${session.lockedNetwork}, cannot pay on ${netConfig.network}`;
        checks.push({ check: "SESSION_NETWORK_LOCK", passed: false, detail: blockSummary });
      }

      if (session.lockedAsset && session.lockedAsset.toLowerCase() !== canonicalAsset) {
        deterministicPassed = false;
        blockReasonCode = "SESSION_ASSET_MISMATCH";
        blockSummary = `Session is locked to asset ${session.lockedAsset}, cannot pay on ${canonicalAsset}`;
        checks.push({ check: "SESSION_ASSET_LOCK", passed: false, detail: blockSummary });
      }
    }

    // 7. Amount & Spend Cap Calculations
    let reqAmountAtomic = 0n;
    let reqUsdMicros = 0n;
    let reqUsdStr = "0";

    if (selectedOption && netConfig) {
      const rawAmt = selectedOption.amount || selectedOption.maxAmountRequired || "";
      if (!/^[1-9]\d*$/.test(String(rawAmt).trim())) {
        deterministicPassed = false;
        blockReasonCode = "INVALID_CHALLENGE_AMOUNT";
        blockSummary = `Invalid challenge token amount: "${rawAmt}" (must be positive integer atomic units)`;
        checks.push({ check: "CHALLENGE_AMOUNT_FORMAT", passed: false, detail: blockSummary });
        reqAmountAtomic = 0n;
        reqUsdMicros = 0n;
        reqUsdStr = "0";
      } else {
        reqAmountAtomic = BigInt(String(rawAmt).trim());
        reqUsdMicros = atomicToUsdMicros(reqAmountAtomic, netConfig.decimals);
        reqUsdStr = formatMicrosToUsd(reqUsdMicros);
        checks.push({
          check: "CHALLENGE_AMOUNT_FORMAT",
          passed: true,
          detail: `Valid atomic amount ${reqAmountAtomic} (${reqUsdStr} USD)`,
        });
      }

      // Advertised price bait-and-switch check
      if (intent.advertisedPriceUsd) {
        try {
          const advMicros = parseUsdToMicros(intent.advertisedPriceUsd);
          if (reqUsdMicros > advMicros) {
            deterministicPassed = false;
            blockReasonCode = "BAIT_AND_SWITCH_PRICE";
            blockSummary = `Merchant challenge price ($${reqUsdStr}) exceeds advertised preflight price ($${intent.advertisedPriceUsd})`;
            checks.push({ check: "PRICE_CONSISTENCY", passed: false, detail: blockSummary });
          } else {
            checks.push({
              check: "PRICE_CONSISTENCY",
              passed: true,
              detail: `Challenge price ($${reqUsdStr}) within advertised range ($${intent.advertisedPriceUsd})`,
            });
          }
        } catch (err) {
          deterministicPassed = false;
          blockReasonCode = "INVALID_ADVERTISED_PRICE";
          blockSummary = `Malformed advertisedPriceUsd: "${intent.advertisedPriceUsd}" (${(err as Error).message})`;
          checks.push({ check: "PRICE_CONSISTENCY", passed: false, detail: blockSummary });
        }
      }

      // Delegation spend cap checks
      if (session) {
        const policy = session.delegation.payment_policy;
        const maxPerTxMicros = parseUsdToMicros(policy.max_amount_per_tx);

        if (reqUsdMicros > maxPerTxMicros) {
          deterministicPassed = false;
          blockReasonCode = "EXCEEDS_MAX_PER_TX";
          blockSummary = `Requested $${reqUsdStr} exceeds delegation max_amount_per_tx ($${policy.max_amount_per_tx})`;
          checks.push({ check: "MAX_PER_TX", passed: false, detail: blockSummary });
        } else {
          checks.push({
            check: "MAX_PER_TX",
            passed: true,
            detail: `Spend $${reqUsdStr} <= limit $${policy.max_amount_per_tx}`,
          });
        }

        if (policy.max_total_amount) {
          const maxTotalMicros = parseUsdToMicros(policy.max_total_amount);
          if (session.cumulativeSpentUsdMicros + reqUsdMicros > maxTotalMicros) {
            deterministicPassed = false;
            blockReasonCode = "EXCEEDS_MAX_TOTAL_BUDGET";
            blockSummary = `Spending $${reqUsdStr} brings total to $${formatMicrosToUsd(session.cumulativeSpentUsdMicros + reqUsdMicros)}, exceeding max_total_amount ($${policy.max_total_amount})`;
            checks.push({ check: "MAX_TOTAL_BUDGET", passed: false, detail: blockSummary });
          } else {
            checks.push({
              check: "MAX_TOTAL_BUDGET",
              passed: true,
              detail: `Cumulative spend within limit ($${formatMicrosToUsd(session.cumulativeSpentUsdMicros)} + $${reqUsdStr} <= $${policy.max_total_amount})`,
            });
          }
        }

        // Daily cap check
        if (session.dailySpentUsdMicros + reqUsdMicros > session.dailyCapUsdMicros) {
          deterministicPassed = false;
          blockReasonCode = "EXCEEDS_DAILY_CAP";
          blockSummary = `Spending $${reqUsdStr} exceeds daily cap ($${formatMicrosToUsd(session.dailyCapUsdMicros)})`;
          checks.push({ check: "DAILY_CAP", passed: false, detail: blockSummary });
        } else {
          checks.push({
            check: "DAILY_CAP",
            passed: true,
            detail: `Daily spend within cap`,
          });
        }
      }
    }

    // 8. Idempotency & Replay Protection
    if (session && idempotencyKey) {
      const existing = session.idempotency.get(idempotencyKey);
      if (existing) {
        if (existing.status === "settled" || existing.status === "in_flight") {
          deterministicPassed = false;
          blockReasonCode = "IDEMPOTENT_REPLAY_DETECTED";
          blockSummary = `Replay detected: idempotencyKey "${idempotencyKey}" already processed with status "${existing.status}"`;
          checks.push({ check: "IDEMPOTENCY_REPLAY", passed: false, detail: blockSummary });
        }
      }
    }

    // 9. EVM Calldata & EIP-712 Firewall Checks
    let evmFirewall: AuditLedgerEntry["evmFirewall"] = undefined;
    let eip712Firewall: AuditLedgerEntry["eip712Firewall"] = undefined;

    if (intent.evmTxOptional) {
      evmFirewall = await simulateEvmTransaction(intent.evmTxOptional);
      if (evmFirewall.verdict === "BLOCK") {
        deterministicPassed = false;
        blockReasonCode = "EVM_FIREWALL_BLOCK";
        blockSummary = `EVM firewall blocked transaction: ${evmFirewall.reasons.join("; ")}`;
        checks.push({ check: "EVM_FIREWALL", passed: false, detail: blockSummary });
      } else {
        checks.push({
          check: "EVM_FIREWALL",
          passed: true,
          detail: `EVM transaction verified safe (riskScore=${evmFirewall.riskScore})`,
        });
      }
    }

    if (intent.eip712Optional) {
      eip712Firewall = inspectEip712TypedData({
        ...intent.eip712Optional,
        expectedPayTo: selectedOption?.payTo || intent.eip712Optional.expectedPayTo,
        maxAllowedAtomic: reqAmountAtomic.toString(),
      });
      if (eip712Firewall.verdict === "BLOCK") {
        deterministicPassed = false;
        blockReasonCode = "EIP712_FIREWALL_BLOCK";
        blockSummary = `EIP-712 firewall blocked signature: ${eip712Firewall.reasons.join("; ")}`;
        checks.push({ check: "EIP712_FIREWALL", passed: false, detail: blockSummary });
      } else {
        checks.push({
          check: "EIP712_FIREWALL",
          passed: true,
          detail: `EIP-712 signature approved (primaryType=${eip712Firewall.primaryType})`,
        });
      }
    }

    // 10. SERV Reasoning (serv_prompt_guard + serv_shadow_agent)
    const servTrace = await evaluateWithServReasoning({
      intent,
      config: this.config,
      selectedOption,
      requestedUsd: reqUsdStr,
    });

    // 11. Final Verdict Synthesizer & Rogue-Model Clamp
    let finalVerdict: FinalSentinelVerdict = "APPROVED";

    if (servTrace.precheckInjection.flagged || servTrace.rawProposal?.promptInjectionDetected) {
      finalVerdict = "BLOCKED_PROMPT_INJECTION";
    } else if (!deterministicPassed) {
      // Deterministic policy ALWAYS overrides LLM APPROVE (Rogue Model Clamp!)
      finalVerdict = "BLOCKED_POLICY_OR_FIREWALL";
    } else if (
      servTrace.rawProposal?.proposedAction === "REJECT_RISK" ||
      servTrace.rawProposal?.proposedAction === "REJECT_VALUE"
    ) {
      finalVerdict = "BLOCKED_POLICY_OR_FIREWALL";
    } else if (
      servTrace.rawProposal?.proposedAction === "HOLD_FOR_APPROVAL" ||
      (session && reqUsdMicros >= session.approvalThresholdUsdMicros) ||
      (evmFirewall && evmFirewall.verdict === "HOLD") ||
      (eip712Firewall && eip712Firewall.verdict === "HOLD")
    ) {
      finalVerdict = "HELD_FOR_HUMAN_APPROVAL";
    } else {
      finalVerdict = "APPROVED";
    }

    // 12. Spend Accounting & Session Lock Update (ONLY upon APPROVED)
    if (finalVerdict === "APPROVED" && session) {
      if (netConfig) {
        if (!session.lockedNetwork) session.lockedNetwork = netConfig.network;
        if (!session.lockedAsset) session.lockedAsset = netConfig.asset;
      }
      session.cumulativeSpentUsdMicros += reqUsdMicros;
      session.dailySpentUsdMicros += reqUsdMicros;
      session.txCount += 1;

      const record: IdempotencyRecord = {
        key: idempotencyKey,
        requestFingerprint: createHash("sha256")
          .update(`${intent.merchantUrl}:${intent.method || "GET"}:${reqUsdStr}`)
          .digest("hex"),
        status: "settled",
        amountUsdMicros: reqUsdMicros.toString(),
        updatedAtIso: timestampIso,
      };
      session.idempotency.set(idempotencyKey, record);
    } else if (session) {
      const record: IdempotencyRecord = {
        key: idempotencyKey,
        requestFingerprint: createHash("sha256")
          .update(`${intent.merchantUrl}:${intent.method || "GET"}:${reqUsdStr}`)
          .digest("hex"),
        status: finalVerdict === "HELD_FOR_HUMAN_APPROVAL" ? "merchant_failed_held" : "rejected",
        amountUsdMicros: reqUsdMicros.toString(),
        updatedAtIso: timestampIso,
      };
      session.idempotency.set(idempotencyKey, record);
    }

    // 13. Construct Audit Ledger Entry
    const explorerBase = netConfig?.explorerUrl || "https://kitescan.ai";
    const payTo = selectedOption?.payTo || CANONICAL_EVM_PAY_TO;

    const partialEntry: Omit<AuditLedgerEntry, "receiptDigestSha256"> = {
      entryId,
      timestampIso,
      sessionId: session?.sessionId || "no-session",
      idempotencyKey,
      merchantUrl: intent.merchantUrl,
      method: (intent.method || "GET").toUpperCase(),
      network: netConfig?.network || "unknown",
      asset: selectedOption?.asset || "0x",
      symbol: netConfig?.symbol || "UNKNOWN",
      requestedAmountAtomic: reqAmountAtomic.toString(),
      requestedAmountUsd: reqUsdStr,
      payTo,
      finalVerdict,
      deterministicRuleVerdict: {
        passed: deterministicPassed,
        code: blockReasonCode,
        summary: blockSummary,
        checks,
      },
      servReasoningExplanation:
        servTrace.rawProposal?.explanation || "Evaluation performed deterministically",
      servTrace,
      evmFirewall,
      eip712Firewall,
      signedPaymentHeaderPreview:
        finalVerdict === "APPROVED"
          ? `PAYMENT-SIGNATURE (x402-v2; net=${netConfig?.network}; amt=${reqAmountAtomic}; to=${payTo})`
          : undefined,
      kpassCliCommand: session
        ? `kpass session status ${session.sessionId}`
        : undefined,
      explorerUrl: `${explorerBase}/address/${payTo}`,
    };

    const receiptDigestSha256 = createHash("sha256")
      .update(
        JSON.stringify({
          entryId: partialEntry.entryId,
          timestampIso: partialEntry.timestampIso,
          sessionId: partialEntry.sessionId,
          finalVerdict: partialEntry.finalVerdict,
          deterministicPassed: partialEntry.deterministicRuleVerdict.passed,
          amountAtomic: partialEntry.requestedAmountAtomic,
          payTo: partialEntry.payTo,
        })
      )
      .digest("hex");

    const fullEntry: AuditLedgerEntry = {
      ...partialEntry,
      receiptDigestSha256,
    };

    this.auditLedger.push(fullEntry);
    return fullEntry;
  }
}
