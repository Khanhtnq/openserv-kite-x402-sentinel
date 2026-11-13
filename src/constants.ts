export const SERVICE_NAME = "openserv-kite-x402-sentinel";
export const SERVICE_VERSION = "1.0.0";

/**
 * Canonical EVM settlement receiver address (Base Mainnet & Kite Chain).
 */
export const CANONICAL_EVM_PAY_TO = "0xcbEDbeCC127a32217075Ff40f16Ec804aa1E0533" as const;

/**
 * Canonical Solana settlement receiver address.
 */
export const CANONICAL_SOLANA_PAY_TO = "6mghraUR9NV2fA187VXoLN2rVS3WLA91UhqLfjtvDdmf" as const;

export interface SettlementNetworkConfig {
  id: "kite-mainnet" | "kite-testnet" | "base-mainnet";
  chainId: number;
  network: `eip155:${number}`;
  displayName: string;
  rpcUrls: readonly string[];
  explorerUrl: string;
  asset: `0x${string}`;
  symbol: string;
  decimals: number;
  eip712Domain: {
    name: string;
    version: string;
  };
  defaultFacilitatorUrl: string;
}

/**
 * Verified network constants matching gokite-ai/kite-x402-services and BrKDDD/kite-x402-hono,
 * plus Base Mainnet USDC for multichain Kite Agent Passport allowance compatibility.
 */
export const SETTLEMENT_NETWORKS: Record<
  "kite-mainnet" | "kite-testnet" | "base-mainnet",
  SettlementNetworkConfig
> = {
  "kite-mainnet": {
    id: "kite-mainnet",
    chainId: 2366,
    network: "eip155:2366",
    displayName: "KiteAI Mainnet",
    rpcUrls: [
      "https://rpc.gokite.ai",
      "https://rpc-virginia.gokite.ai",
      "https://rpc-ireland.gokite.ai",
    ],
    explorerUrl: "https://kitescan.ai",
    asset: "0x7aB6f3ed87C42eF0aDb67Ed95090f8bF5240149e",
    symbol: "USDC.e",
    decimals: 6,
    eip712Domain: {
      name: "Bridged USDC (Kite AI)",
      version: "2",
    },
    defaultFacilitatorUrl: "https://facilitator.pieverse.io/v2",
  },
  "kite-testnet": {
    id: "kite-testnet",
    chainId: 2368,
    network: "eip155:2368",
    displayName: "KiteAI Testnet",
    rpcUrls: ["https://rpc-testnet.gokite.ai"],
    explorerUrl: "https://testnet.kitescan.ai",
    asset: "0x38129cf4CE5E183eFF248F42A7D345Bb1B47621A",
    symbol: "pieUSD",
    decimals: 18,
    eip712Domain: {
      name: "pieUSD",
      version: "1",
    },
    defaultFacilitatorUrl: "https://facilitator.pieverse.io/v2",
  },
  "base-mainnet": {
    id: "base-mainnet",
    chainId: 8453,
    network: "eip155:8453",
    displayName: "Base Mainnet",
    rpcUrls: [
      "https://mainnet.base.org",
      "https://base-rpc.publicnode.com",
    ],
    explorerUrl: "https://basescan.org",
    asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    symbol: "USDC",
    decimals: 6,
    eip712Domain: {
      name: "USD Coin",
      version: "2",
    },
    defaultFacilitatorUrl: "https://facilitator.payai.network",
  },
};

/**
 * Backwards-compatible alias matching BrKDDD/kite-x402-hono KITE_NETWORKS export.
 */
export const KITE_NETWORKS = {
  mainnet: {
    network: SETTLEMENT_NETWORKS["kite-mainnet"].network,
    chainId: SETTLEMENT_NETWORKS["kite-mainnet"].chainId,
    rpcUrl: SETTLEMENT_NETWORKS["kite-mainnet"].rpcUrls[0]!,
    explorerUrl: SETTLEMENT_NETWORKS["kite-mainnet"].explorerUrl,
    asset: SETTLEMENT_NETWORKS["kite-mainnet"].asset,
    symbol: SETTLEMENT_NETWORKS["kite-mainnet"].symbol,
    decimals: SETTLEMENT_NETWORKS["kite-mainnet"].decimals,
    name: SETTLEMENT_NETWORKS["kite-mainnet"].eip712Domain.name,
    version: SETTLEMENT_NETWORKS["kite-mainnet"].eip712Domain.version,
  },
  testnet: {
    network: SETTLEMENT_NETWORKS["kite-testnet"].network,
    chainId: SETTLEMENT_NETWORKS["kite-testnet"].chainId,
    rpcUrl: SETTLEMENT_NETWORKS["kite-testnet"].rpcUrls[0]!,
    explorerUrl: SETTLEMENT_NETWORKS["kite-testnet"].explorerUrl,
    asset: SETTLEMENT_NETWORKS["kite-testnet"].asset,
    symbol: SETTLEMENT_NETWORKS["kite-testnet"].symbol,
    decimals: SETTLEMENT_NETWORKS["kite-testnet"].decimals,
    name: SETTLEMENT_NETWORKS["kite-testnet"].eip712Domain.name,
    version: SETTLEMENT_NETWORKS["kite-testnet"].eip712Domain.version,
  },
} as const;

export const PIEVERSE_FACILITATOR_V2_URL = "https://facilitator.pieverse.io/v2" as const;
export const PAYAI_FACILITATOR_URL = "https://facilitator.payai.network" as const;

/**
 * OpenServ SERV Reasoning API constants (verified from https://docs.openserv.ai/serv-reasoning).
 * - OpenAI-compatible baseURL MUST include `/v1`.
 * - Every request MUST contain a `system` prompt (HTTP 400 if omitted).
 * - `serv_prompt_guard` and `serv_shadow_agent` are declared via `tools` array (server-stripped).
 * - Multipath is enabled via `-serv-multipath` suffix on small catalog models.
 * - Kronos (`-serv-kronos`) is intentionally disabled so strict JSON schema output is never rewritten.
 */
export const SERV_REASONING_BASE_URL = "https://inference-api.openserv.ai/v1" as const;
export const SERV_DEFAULT_MODEL = "gpt-5.4-mini-serv-multipath" as const;
export const SERV_FALLBACK_MODEL = "gpt-5.4-mini" as const;
export const SERV_SYSTEM_PROMPT_VERSION = "sentinel-policy-v1.2.0" as const;

export const DEFAULT_SELLER_PRICE_USD = "0.001" as const;

export const PERMIT2_CANONICAL_ADDRESS = "0x000000000022D473030F116dDEE9F6B43aC78BA3" as const;
export const MAX_UINT128 = (1n << 128n) - 1n;
export const MAX_UINT256 = (1n << 256n) - 1n;

export function resolveSettlementNetwork(
  identifier: string | number | undefined | null
): SettlementNetworkConfig | undefined {
  if (identifier === undefined || identifier === null) return undefined;
  const norm = String(identifier).trim().toLowerCase();
  if (
    norm === "mainnet" ||
    norm === "kite" ||
    norm === "kite-mainnet" ||
    norm === "2366" ||
    norm === "0x93e" ||
    norm === "eip155:2366"
  ) {
    return SETTLEMENT_NETWORKS["kite-mainnet"];
  }
  if (
    norm === "testnet" ||
    norm === "kite-testnet" ||
    norm === "2368" ||
    norm === "0x940" ||
    norm === "eip155:2368"
  ) {
    return SETTLEMENT_NETWORKS["kite-testnet"];
  }
  if (
    norm === "base" ||
    norm === "base-mainnet" ||
    norm === "8453" ||
    norm === "0x2105" ||
    norm === "eip155:8453"
  ) {
    return SETTLEMENT_NETWORKS["base-mainnet"];
  }
  return undefined;
}
