import {
  KiteDelegation,
  KiteDelegationSchema,
  KiteSessionRuntimeState,
} from "./types.js";

/**
 * Strict non-negative decimal string parsing up to 6 decimals into integer micros (10^6).
 * Zero floating-point drift.
 */
export function parseUsdToMicros(usd: string): bigint {
  const trimmed = usd.trim();
  if (!/^(?:0|[1-9]\d*)(?:\.\d{1,6})?$/.test(trimmed)) {
    throw new Error(`Invalid USD amount format: "${usd}" (must be non-negative with up to 6 decimals)`);
  }
  const parts = trimmed.split(".");
  const intPart = BigInt(parts[0] || "0");
  const fracPart = parts[1] || "";
  const paddedFrac = (fracPart + "000000").slice(0, 6);
  return intPart * 1_000_000n + BigInt(paddedFrac);
}

/**
 * Formats USD integer micros (10^6) back into decimal string.
 */
export function formatMicrosToUsd(micros: bigint): string {
  if (micros < 0n) {
    throw new Error(`USD micros cannot be negative: ${micros}`);
  }
  const intPart = micros / 1_000_000n;
  const fracPart = micros % 1_000_000n;
  if (fracPart === 0n) {
    return intPart.toString();
  }
  const fracStr = fracPart.toString().padStart(6, "0").replace(/0+$/, "");
  return `${intPart}.${fracStr}`;
}

/**
 * Converts token atomic units to USD micros (10^6) using ceiling rounding:
 * ((amountAtomic * 1_000_000n + scale - 1n) / scale)
 * Sub-micro dust can never bypass spend limits!
 */
export function atomicToUsdMicros(amountAtomic: bigint, decimals: number): bigint {
  if (amountAtomic < 0n) {
    throw new Error(`atomic amount cannot be negative: ${amountAtomic}`);
  }
  if (decimals < 0 || decimals > 255) {
    throw new Error(`invalid decimals: ${decimals}`);
  }
  if (amountAtomic === 0n) return 0n;

  if (decimals === 6) {
    return amountAtomic;
  }

  const scale = 10n ** BigInt(decimals);
  return (amountAtomic * 1_000_000n + scale - 1n) / scale;
}

const PRIVATE_IPV4_PATTERNS = [
  /^0\./,                           // 0.0.0.0/8
  /^127\./,                         // 127.0.0.0/8 loopback
  /^10\./,                          // 10.0.0.0/8
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // 100.64.0.0/10 CGNAT
  /^172\.(1[6-9]|2\d|3[01])\./,     // 172.16.0.0/12
  /^192\.168\./,                    // 192.168.0.0/16
  /^169\.254\./,                    // 169.254.0.0/16 link-local
];

function isPrivateOrLoopbackIp(host: string): boolean {
  const cleanHost = host.replace(/^\[|\]$/g, "").toLowerCase();

  // IPv4 check
  for (const pattern of PRIVATE_IPV4_PATTERNS) {
    if (pattern.test(cleanHost)) return true;
  }

  // IPv6 check
  if (
    cleanHost === "::1" ||
    cleanHost === "0:0:0:0:0:0:0:1" ||
    cleanHost === "::" ||
    cleanHost.startsWith("fc") ||
    cleanHost.startsWith("fd") ||
    cleanHost.startsWith("fe80:")
  ) {
    return true;
  }

  // IPv4-mapped IPv6 address (e.g., ::ffff:127.0.0.1 or Node-normalized hex ::ffff:7f00:1)
  if (cleanHost.startsWith("::ffff:")) {
    const tail = cleanHost.replace("::ffff:", "");
    if (tail.includes(".")) {
      for (const pattern of PRIVATE_IPV4_PATTERNS) {
        if (pattern.test(tail)) return true;
      }
    } else if (tail.includes(":")) {
      const parts = tail.split(":");
      if (parts.length === 2 && parts[0] && parts[1]) {
        const p1 = parseInt(parts[0], 16);
        const p2 = parseInt(parts[1], 16);
        if (!isNaN(p1) && !isNaN(p2)) {
          const b1 = (p1 >> 8) & 0xff;
          const b2 = p1 & 0xff;
          const b3 = (p2 >> 8) & 0xff;
          const b4 = p2 & 0xff;
          const decodedV4 = `${b1}.${b2}.${b3}.${b4}`;
          for (const pattern of PRIVATE_IPV4_PATTERNS) {
            if (pattern.test(decodedV4)) return true;
          }
        }
      }
    } else {
      // Any other non-standard ::ffff format
      return true;
    }
  }

  return false;
}

/**
 * Validates merchant URL safety (SSRF protection).
 * Enforces https:// unless allowLocalhost === true for local test addresses.
 * Blocks URL userinfo, private/loopback/link-local IPv4 & IPv6, and .localhost/.internal domains.
 */
export function validateMerchantUrlSafety(
  urlStr: string,
  allowLocalhost: boolean = false
): {
  ok: boolean;
  normalizedUrl?: string;
  host?: string;
  pathname?: string;
  reason?: string;
} {
  if (!urlStr || typeof urlStr !== "string") {
    return { ok: false, reason: "Merchant URL is required and must be a string" };
  }

  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    return { ok: false, reason: `Invalid URL format: "${urlStr}"` };
  }

  if (parsed.username || parsed.password) {
    return { ok: false, reason: "Merchant URL must not contain userinfo credentials (@)" };
  }

  const hostLower = parsed.hostname.toLowerCase();
  const isLocalhostHost =
    hostLower === "localhost" ||
    hostLower === "127.0.0.1" ||
    hostLower === "[::1]" ||
    hostLower === "::1";

  if (allowLocalhost && isLocalhostHost) {
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { ok: false, reason: `Localhost URL must use http: or https: (got ${parsed.protocol})` };
    }
    return {
      ok: true,
      normalizedUrl: parsed.toString(),
      host: hostLower,
      pathname: parsed.pathname || "/",
    };
  }

  if (parsed.protocol !== "https:") {
    return {
      ok: false,
      reason: `Merchant URL must use https:// protocol (got ${parsed.protocol})`,
    };
  }

  if (isLocalhostHost || hostLower.endsWith(".localhost") || hostLower.endsWith(".internal")) {
    return {
      ok: false,
      reason: `Merchant host "${hostLower}" resolves to loopback or internal domain`,
    };
  }

  if (isPrivateOrLoopbackIp(hostLower)) {
    return {
      ok: false,
      reason: `Merchant host "${hostLower}" resolves to private/loopback/link-local IP`,
    };
  }

  return {
    ok: true,
    normalizedUrl: parsed.toString(),
    host: hostLower,
    pathname: parsed.pathname || "/",
  };
}

/**
 * Shell escape helper for safe kpass CLI emission (single-quote wrapping with escape)
 */
function shellEscape(arg: string): string {
  return `'${arg.replace(/'/g, "'\\''")}'`;
}

/**
 * Compiles and validates a strict Kite Agent Passport delegation JSON
 * and generates a shell-safe kpass CLI command.
 */
export function compileKiteDelegation(params: {
  taskSummary: string;
  merchantUrl: string;
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD";
  preflightPriceUsd: string;
  estimatedRequests: number;
  ttlSeconds: number;
  safetyBufferBps?: number;
  routingEnabled?: boolean;
  allowLocalhostMerchantUrls?: boolean;
}): {
  delegation: KiteDelegation;
  kpassCliCommand: string;
  maxTotalUsd: string;
} {
  const urlCheck = validateMerchantUrlSafety(
    params.merchantUrl,
    params.allowLocalhostMerchantUrls ?? false
  );
  if (!urlCheck.ok || !urlCheck.host || !urlCheck.pathname) {
    throw new Error(`Merchant URL rejected: ${urlCheck.reason}`);
  }

  const preflightMicros = parseUsdToMicros(params.preflightPriceUsd);
  if (preflightMicros <= 0n) {
    throw new Error("preflightPriceUsd must be strictly positive");
  }
  if (params.estimatedRequests <= 0) {
    throw new Error("estimatedRequests must be an integer >= 1");
  }
  if (params.ttlSeconds <= 0) {
    throw new Error("ttlSeconds must be an integer >= 1");
  }

  const safetyBufferBps = BigInt(params.safetyBufferBps ?? 1500); // 15% default buffer
  const bufferMicros = (preflightMicros * safetyBufferBps) / 10000n;
  const maxPerTxMicros = preflightMicros + bufferMicros;
  const maxTotalMicros = maxPerTxMicros * BigInt(params.estimatedRequests);

  const maxPerTxUsd = formatMicrosToUsd(maxPerTxMicros);
  const maxTotalUsd = formatMicrosToUsd(maxTotalMicros);

  const method = params.method || "GET";

  const rawDelegation = {
    task: {
      summary: params.taskSummary.slice(0, 160),
    },
    payment_policy: {
      max_amount_per_tx: maxPerTxUsd,
      max_total_amount: maxTotalUsd,
      ttl_seconds: params.ttlSeconds,
      currency: "USD" as const,
    },
    execution_constraints: {
      x402: {
        scope_mode: "scoped" as const,
        allowed_endpoints: [
          {
            method,
            host: urlCheck.host,
            path_prefix: urlCheck.pathname,
          },
        ],
      },
    },
    routing_enabled: params.routingEnabled ?? false,
    routing_cost_cap_usd_micros: 0,
  };

  const validated = KiteDelegationSchema.parse(rawDelegation);

  const jsonStr = JSON.stringify(validated);
  const kpassCliCommand = `kpass session create --policy ${shellEscape(jsonStr)}`;

  return {
    delegation: validated,
    kpassCliCommand,
    maxTotalUsd,
  };
}

/**
 * Creates an in-memory runtime session tracking state with BigInt spend counters
 * and idempotency replay tables.
 */
export function createSessionRuntimeState(params: {
  sessionId?: string;
  userRootAddress: `0x${string}`;
  agentDelegatedAddress: `0x${string}`;
  ephemeralSessionAddress: `0x${string}`;
  delegation: KiteDelegation;
  issuedAtSec?: number;
  approvalThresholdUsdMicros?: bigint;
  dailyCapUsdMicros?: bigint;
  mandateSignature?: `0x${string}`;
}): KiteSessionRuntimeState {
  const now = params.issuedAtSec ?? Math.floor(Date.now() / 1000);
  const ttl = params.delegation.payment_policy.ttl_seconds;
  const expiresAtSec = now + ttl;

  const maxTotalUsd = params.delegation.payment_policy.max_total_amount;
  const defaultDailyCap = maxTotalUsd
    ? parseUsdToMicros(maxTotalUsd)
    : 10_000_000n; // $10.00 fallback

  const defaultApprovalThreshold = 5_000_000n; // $5.00 default threshold

  const sid =
    params.sessionId ||
    `kpass-sess-${Math.random().toString(36).substring(2, 10)}-${Date.now().toString(36)}`;

  return {
    sessionId: sid,
    userRootAddress: params.userRootAddress,
    agentDelegatedAddress: params.agentDelegatedAddress,
    ephemeralSessionAddress: params.ephemeralSessionAddress,
    delegation: params.delegation,
    issuedAtSec: now,
    expiresAtSec,
    approvalThresholdUsdMicros: params.approvalThresholdUsdMicros ?? defaultApprovalThreshold,
    dailyCapUsdMicros: params.dailyCapUsdMicros ?? defaultDailyCap,
    cumulativeSpentUsdMicros: 0n,
    dailySpentUsdMicros: 0n,
    txCount: 0,
    lockedNetwork: null,
    lockedAsset: null,
    mandateSignature: params.mandateSignature,
    idempotency: new Map(),
  };
}
