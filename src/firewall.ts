import {
  DecodedCallSummary,
  Eip712FirewallReport,
  EvmFirewallReport,
  InspectEip712Input,
  SimulateEvmTxInput,
} from "./types.js";
import {
  MAX_UINT128,
  resolveSettlementNetwork,
  SETTLEMENT_NETWORKS,
} from "./constants.js";

// Canonical Selectors
const SELECTORS = {
  ERC20_APPROVE: "0x095ea7b3",
  ERC20_INCREASE_ALLOWANCE: "0x39509351",
  ERC20_TRANSFER: "0xa9059cbb",
  ERC20_TRANSFER_FROM: "0x23b872dd",
  PERMIT2_APPROVE: "0x87517c45",
  PERMIT2_PERMIT: "0x2b67b570",
  NFT_SET_APPROVAL_FOR_ALL: "0xa22cb465",
  MULTICALL_V1: "0xac9650d8", // multicall(bytes[])
  MULTICALL_V2: "0x5ae401dc", // multicall(uint256,bytes[])
  MULTICALL_V3: "0x252dba42", // aggregate((address,bytes)[])
  ERC20_BALANCE_OF: "0x70a08231",
} as const;

function cleanHex(hex: string): string {
  return hex.startsWith("0x") ? hex.slice(2).toLowerCase() : hex.toLowerCase();
}

function parseAddressFromWord(wordHex: string): string {
  const clean = cleanHex(wordHex).padStart(64, "0");
  return `0x${clean.slice(24, 64)}`;
}

function parseBigIntFromWord(wordHex: string): { ok: boolean; val: bigint } {
  try {
    const clean = cleanHex(wordHex).padStart(64, "0");
    return { ok: true, val: BigInt(`0x${clean}`) };
  } catch {
    return { ok: false, val: 0n };
  }
}

function safeParseBigInt(val: unknown): { ok: boolean; val: bigint } {
  try {
    if (typeof val === "bigint") return { ok: true, val };
    const str = String(val).trim();
    if (!str || str === "0x") return { ok: true, val: 0n };
    if (str.startsWith("0x") || str.startsWith("0X")) {
      return { ok: true, val: BigInt(str) };
    }
    return { ok: true, val: BigInt(str) };
  } catch {
    return { ok: false, val: 0n };
  }
}

/**
 * Decodes the function selector and parameters of an EVM transaction data payload.
 */
export function decodeCalldata(
  to: string | null,
  data?: string,
  value?: string
): DecodedCallSummary {
  const cleanData = data ? cleanHex(data) : "";
  const valParsed = safeParseBigInt(value);
  const hasValue = valParsed.ok && valParsed.val > 0n;

  if (to === null || to === "" || to === "0x") {
    return {
      selector: "0x",
      signature: "contract_creation()",
      category: "CONTRACT_CREATION",
      isUnlimitedApproval: false,
    };
  }

  if (cleanData.length < 8) {
    if (hasValue) {
      return {
        selector: "0x",
        signature: "native_transfer()",
        category: "NATIVE_TRANSFER",
        spenderOrRecipient: to,
        amountAtomic: valParsed.val.toString(),
        isUnlimitedApproval: false,
      };
    }
    return {
      selector: "0x",
      signature: "empty_or_fallback()",
      category: "READ_ONLY",
      isUnlimitedApproval: false,
    };
  }

  const selector = `0x${cleanData.slice(0, 8)}`.toLowerCase();
  const calldataBody = cleanData.slice(8);

  switch (selector) {
    case SELECTORS.ERC20_APPROVE: {
      const spender = calldataBody.length >= 64 ? parseAddressFromWord(calldataBody.slice(0, 64)) : undefined;
      const amtParsed = calldataBody.length >= 128 ? parseBigIntFromWord(calldataBody.slice(64, 128)) : { ok: true, val: 0n };
      const amount = amtParsed.val;
      const isUnlimited = amount >= MAX_UINT128;
      return {
        selector,
        signature: "approve(address,uint256)",
        category: "ERC20_APPROVAL",
        spenderOrRecipient: spender,
        amountAtomic: amount.toString(),
        isUnlimitedApproval: isUnlimited,
      };
    }

    case SELECTORS.ERC20_INCREASE_ALLOWANCE: {
      const spender = calldataBody.length >= 64 ? parseAddressFromWord(calldataBody.slice(0, 64)) : undefined;
      const amtParsed = calldataBody.length >= 128 ? parseBigIntFromWord(calldataBody.slice(64, 128)) : { ok: true, val: 0n };
      const amount = amtParsed.val;
      const isUnlimited = amount >= MAX_UINT128;
      return {
        selector,
        signature: "increaseAllowance(address,uint256)",
        category: "ERC20_APPROVAL",
        spenderOrRecipient: spender,
        amountAtomic: amount.toString(),
        isUnlimitedApproval: isUnlimited,
      };
    }

    case SELECTORS.ERC20_TRANSFER: {
      const recipient = calldataBody.length >= 64 ? parseAddressFromWord(calldataBody.slice(0, 64)) : undefined;
      const amtParsed = calldataBody.length >= 128 ? parseBigIntFromWord(calldataBody.slice(64, 128)) : { ok: true, val: 0n };
      return {
        selector,
        signature: "transfer(address,uint256)",
        category: "ERC20_TRANSFER",
        spenderOrRecipient: recipient,
        amountAtomic: amtParsed.val.toString(),
        isUnlimitedApproval: false,
      };
    }

    case SELECTORS.ERC20_TRANSFER_FROM: {
      const recipient = calldataBody.length >= 128 ? parseAddressFromWord(calldataBody.slice(64, 128)) : undefined;
      const amtParsed = calldataBody.length >= 192 ? parseBigIntFromWord(calldataBody.slice(128, 192)) : { ok: true, val: 0n };
      return {
        selector,
        signature: "transferFrom(address,address,uint256)",
        category: "ERC20_TRANSFER",
        spenderOrRecipient: recipient,
        amountAtomic: amtParsed.val.toString(),
        isUnlimitedApproval: false,
      };
    }

    case SELECTORS.PERMIT2_APPROVE: {
      const token = calldataBody.length >= 64 ? parseAddressFromWord(calldataBody.slice(0, 64)) : undefined;
      const spender = calldataBody.length >= 128 ? parseAddressFromWord(calldataBody.slice(64, 128)) : undefined;
      const amtParsed = calldataBody.length >= 192 ? parseBigIntFromWord(calldataBody.slice(128, 192)) : { ok: true, val: 0n };
      const amount = amtParsed.val;
      return {
        selector,
        signature: "permit2_approve(address,address,uint160,uint48)",
        category: "PERMIT2",
        spenderOrRecipient: spender ?? token,
        amountAtomic: amount.toString(),
        isUnlimitedApproval: amount >= MAX_UINT128,
      };
    }

    case SELECTORS.PERMIT2_PERMIT: {
      return {
        selector,
        signature: "permit2_permit(address,PermitSingle,bytes)",
        category: "PERMIT2",
        isUnlimitedApproval: false,
      };
    }

    case SELECTORS.NFT_SET_APPROVAL_FOR_ALL: {
      const operator = calldataBody.length >= 64 ? parseAddressFromWord(calldataBody.slice(0, 64)) : undefined;
      return {
        selector,
        signature: "setApprovalForAll(address,bool)",
        category: "NFT_APPROVAL_ALL",
        spenderOrRecipient: operator,
        isUnlimitedApproval: true,
      };
    }

    case SELECTORS.MULTICALL_V1:
    case SELECTORS.MULTICALL_V2:
    case SELECTORS.MULTICALL_V3: {
      return {
        selector,
        signature: "multicall(bytes[])",
        category: "MULTICALL",
        isUnlimitedApproval: false,
      };
    }

    case SELECTORS.ERC20_BALANCE_OF: {
      return {
        selector,
        signature: "balanceOf(address)",
        category: "READ_ONLY",
        isUnlimitedApproval: false,
      };
    }

    default: {
      return {
        selector,
        signature: `unknown_selector(${selector})`,
        category: "UNKNOWN_CALL",
        isUnlimitedApproval: false,
      };
    }
  }
}

/**
 * Simulates and audits an EVM transaction before signing/broadcast.
 * Flags EIP-7702 delegation hijacks, unlimited approvals, opaque multicalls, and contract creations.
 */
export async function simulateEvmTransaction(
  input: SimulateEvmTxInput
): Promise<EvmFirewallReport> {
  const reasons: string[] = [];
  let riskScore = 0;

  const netConfig = resolveSettlementNetwork(input.chainId);
  const chainIdNum = netConfig ? netConfig.chainId : (typeof input.chainId === "string" ? parseInt(input.chainId, 10) : input.chainId);
  const networkName = netConfig ? netConfig.displayName : `Unknown Chain ${chainIdNum}`;

  // 1. EIP-7702 EOA Code-Delegation Hijack Check
  if (input.authorizationList && input.authorizationList.length > 0) {
    riskScore += 95;
    reasons.push(
      `CRITICAL: EIP-7702 authorizationList present with ${input.authorizationList.length} delegation entries! Potential EOA account code hijack.`
    );
  }

  // 2. Decode Calldata
  const decoded = decodeCalldata(input.to, input.data, input.value);

  // 3. Spender Whitelist Check
  const trustedSpenders = (input.trustedSpenders || []).map((s) => s.toLowerCase());

  if (decoded.category === "CONTRACT_CREATION") {
    riskScore += 90;
    reasons.push("CRITICAL: Transaction creates a new unverified contract (to is null)");
  } else if (decoded.category === "NFT_APPROVAL_ALL") {
    riskScore += 90;
    reasons.push("CRITICAL: setApprovalForAll called granting blanket access to all NFT assets");
  } else if (decoded.category === "ERC20_APPROVAL") {
    const spender = (decoded.spenderOrRecipient || "").toLowerCase();
    const isTrusted = trustedSpenders.includes(spender);

    if (decoded.isUnlimitedApproval) {
      if (!isTrusted) {
        riskScore += 85;
        reasons.push(`HIGH: Unlimited token allowance granted to untrusted spender (${decoded.spenderOrRecipient})`);
      } else {
        riskScore += 25;
        reasons.push(`LOW: Unlimited token allowance to trusted spender (${decoded.spenderOrRecipient})`);
      }
    } else {
      if (!isTrusted && spender) {
        riskScore += 30;
        reasons.push(`MEDIUM: Token approval to non-whitelisted spender (${decoded.spenderOrRecipient})`);
      }
    }
  } else if (decoded.category === "MULTICALL") {
    riskScore += 65;
    reasons.push("HOLD: Opaque multicall batch detected; individual calls must be unbundled and verified");
  } else if (decoded.category === "UNKNOWN_CALL") {
    riskScore += 50;
    reasons.push(`MEDIUM: Unknown function selector ${decoded.selector}`);
  }

  // 4. Determine Verdict & Tier
  riskScore = Math.min(100, Math.max(0, riskScore));
  let verdict: EvmFirewallReport["verdict"] = "ALLOW";
  let riskTier: EvmFirewallReport["riskTier"] = "SAFE";

  if (riskScore >= 70) {
    verdict = "BLOCK";
    riskTier = riskScore >= 90 ? "CRITICAL" : "HIGH";
  } else if (riskScore >= 40) {
    verdict = "HOLD";
    riskTier = "MEDIUM";
  } else if (riskScore > 0) {
    riskTier = "LOW";
  }

  if (reasons.length === 0) {
    reasons.push("All deterministic EVM calldata and EIP-7702 checks passed cleanly.");
  }

  // 5. Optional Live RPC Simulation (viem / JSON-RPC eth_call)
  const rpcSimulation: EvmFirewallReport["rpcSimulation"] = {
    attempted: false,
  };

  if (input.runLiveRpcEthCall && netConfig && netConfig.rpcUrls.length > 0) {
    const rpcUrl = netConfig.rpcUrls[0]!;
    rpcSimulation.attempted = true;
    rpcSimulation.rpcUrl = rpcUrl;
    const startMs = Date.now();

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);

      const chainIdRes = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "eth_chainId",
          params: [],
        }),
        signal: controller.signal,
      });

      const chainIdJson = (await chainIdRes.json()) as { result?: string };
      if (chainIdJson.result) {
        rpcSimulation.chainIdVerified = parseInt(chainIdJson.result, 16);
      }

      const callRes = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "eth_call",
          params: [
            {
              from: input.from,
              to: input.to,
              data: input.data || "0x",
              value: input.value || "0x0",
            },
            "latest",
          ],
        }),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      const callJson = (await callRes.json()) as { result?: string; error?: { message?: string } };
      rpcSimulation.latencyMs = Date.now() - startMs;

      if (callJson.error) {
        rpcSimulation.ethCallSuccess = false;
        rpcSimulation.returnDataOrError = callJson.error.message || JSON.stringify(callJson.error);
        riskScore = Math.max(riskScore, 75);
        verdict = "BLOCK";
        reasons.push(`LIVE RPC eth_call REVERT: ${rpcSimulation.returnDataOrError}`);
      } else {
        rpcSimulation.ethCallSuccess = true;
        rpcSimulation.returnDataOrError = callJson.result;
      }
    } catch (err) {
      rpcSimulation.latencyMs = Date.now() - startMs;
      rpcSimulation.ethCallSuccess = false;
      rpcSimulation.returnDataOrError = (err as Error).message;
    }
  }

  return {
    verdict,
    riskScore,
    riskTier,
    chainId: chainIdNum,
    networkName,
    decodedCall: decoded,
    reasons,
    rpcSimulation,
  };
}

/**
 * Audits EIP-712 typed data signatures (EIP-3009 TransferWithAuthorization,
 * ERC-2612 Permit, PermitSingle, PermitBatch) to prevent phishing and unauthorized drains.
 */
export function inspectEip712TypedData(input: InspectEip712Input): Eip712FirewallReport {
  const reasons: string[] = [];
  let riskScore = 0;
  const primaryType = input.primaryType;

  const msg = input.message || {};
  const expectedPayTo = input.expectedPayTo?.toLowerCase();
  const maxAllowedParsed = input.maxAllowedAtomic ? safeParseBigInt(input.maxAllowedAtomic) : undefined;
  const maxAllowedAtomic = maxAllowedParsed && maxAllowedParsed.ok ? maxAllowedParsed.val : undefined;

  // 1. Audit EIP-3009 TransferWithAuthorization / ReceiveWithAuthorization
  if (
    primaryType === "TransferWithAuthorization" ||
    primaryType === "ReceiveWithAuthorization"
  ) {
    const to = typeof msg.to === "string" ? msg.to.toLowerCase() : undefined;
    const payee = typeof msg.payee === "string" ? msg.payee.toLowerCase() : undefined;
    const recipient = to ?? payee;

    if (expectedPayTo && recipient && recipient !== expectedPayTo) {
      riskScore += 95;
      reasons.push(`CRITICAL: EIP-3009 recipient (${recipient}) does not match expected payTo (${expectedPayTo})`);
    }

    if (msg.value !== undefined) {
      const valParsed = safeParseBigInt(msg.value);
      if (!valParsed.ok) {
        riskScore = 100;
        reasons.push(`CRITICAL: Malformed non-numeric EIP-3009 value (${String(msg.value)})`);
      } else {
        const val = valParsed.val;
        if (maxAllowedAtomic !== undefined && val > maxAllowedAtomic) {
          riskScore += 90;
          reasons.push(`CRITICAL: EIP-3009 amount (${val}) exceeds allowed max (${maxAllowedAtomic})`);
        }
      }
    }

    // Check validAfter and validBefore
    const now = Math.floor(Date.now() / 1000);
    if (msg.validBefore !== undefined && Number(msg.validBefore) <= now) {
      riskScore += 60;
      reasons.push(`HIGH: EIP-3009 authorization has already expired (validBefore=${msg.validBefore})`);
    }
  }

  // 2. Audit ERC-2612 Permit
  else if (primaryType === "Permit") {
    const spender = typeof msg.spender === "string" ? msg.spender.toLowerCase() : undefined;
    if (expectedPayTo && spender && spender !== expectedPayTo) {
      riskScore += 90;
      reasons.push(`CRITICAL: Permit spender (${spender}) does not match expected recipient (${expectedPayTo})`);
    }

    if (msg.value !== undefined) {
      const valParsed = safeParseBigInt(msg.value);
      if (!valParsed.ok) {
        riskScore = 100;
        reasons.push(`CRITICAL: Malformed non-numeric Permit value (${String(msg.value)})`);
      } else {
        const val = valParsed.val;
        if (val >= MAX_UINT128) {
          riskScore += 85;
          reasons.push("HIGH: Permit grants unlimited allowance (max uint)");
        } else if (maxAllowedAtomic !== undefined && val > maxAllowedAtomic) {
          riskScore += 80;
          reasons.push(`HIGH: Permit allowance (${val}) exceeds maximum allowed (${maxAllowedAtomic})`);
        }
      }
    }
  }

  // 3. Audit Uniswap Permit2 (PermitSingle / PermitBatch)
  else if (primaryType === "PermitSingle") {
    const spender = typeof msg.spender === "string" ? msg.spender.toLowerCase() : undefined;
    if (expectedPayTo && spender && spender !== expectedPayTo) {
      riskScore += 90;
      reasons.push(`CRITICAL: Permit2 spender (${spender}) does not match expected (${expectedPayTo})`);
    }

    const details = msg.details as { amount?: string | number } | undefined;
    if (details && details.amount !== undefined) {
      const amtParsed = safeParseBigInt(details.amount);
      if (!amtParsed.ok) {
        riskScore = 100;
        reasons.push(`CRITICAL: Malformed non-numeric PermitSingle amount (${String(details.amount)})`);
      } else {
        const amt = amtParsed.val;
        if (amt >= MAX_UINT128) {
          riskScore += 85;
          reasons.push("HIGH: PermitSingle specifies unlimited token amount");
        } else if (maxAllowedAtomic !== undefined && amt > maxAllowedAtomic) {
          riskScore += 80;
          reasons.push(`HIGH: PermitSingle amount (${amt}) exceeds maximum allowed (${maxAllowedAtomic})`);
        }
      }
    }
  } else if (primaryType === "PermitBatch") {
    riskScore += 70;
    reasons.push("HOLD: PermitBatch approves multi-token access; requires manual confirmation");
  }

  // 4. Verify Domain Asset/Chain
  if (input.domain.chainId !== undefined) {
    const chainIdNum = typeof input.domain.chainId === "string"
      ? parseInt(input.domain.chainId, 10)
      : input.domain.chainId;
    const net = resolveSettlementNetwork(chainIdNum);
    if (net && input.domain.verifyingContract) {
      const contract = input.domain.verifyingContract.toLowerCase();
      if (contract !== net.asset.toLowerCase()) {
        riskScore += 40;
        reasons.push(`MEDIUM: Verifying contract ${contract} does not match canonical settlement asset for chain ${chainIdNum} (${net.asset})`);
      }
    }
  }

  // Verdict
  riskScore = Math.min(100, Math.max(0, riskScore));
  let verdict: Eip712FirewallReport["verdict"] = "ALLOW";
  if (riskScore >= 70) {
    verdict = "BLOCK";
  } else if (riskScore >= 40) {
    verdict = "HOLD";
  }

  if (reasons.length === 0) {
    reasons.push("EIP-712 typed data passed all security invariants.");
  }

  return {
    verdict,
    riskScore,
    primaryType,
    reasons,
  };
}
