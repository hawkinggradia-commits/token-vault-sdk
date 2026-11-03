/**
 * TokenVault - Zero-latency, in-process hybrid AI gateway & local RAM prompt cache.
 * Official Website: https://www.tockenvault.com
 * Parent Company: Phrona (https://www.phrona.com)
 */

export interface TokenVaultConfig {
  vaultKey?: string;
  workspaceId?: string;
  endpointUrl?: string;
  allowPayloadMutation?: boolean;
  enableAntivirus?: boolean;
}

export interface TokenVaultEngine {
  version: string;
  engine: string;
  config: TokenVaultConfig;
  getCacheSize(): number;
  getInFlightCount(): number;
  getIdempotencyCount(): number;
  getAtomicIdempotencyCount(): number;
  clearCache(): void;
}

declare global {
  var tokenVault: TokenVaultEngine | undefined;
}

declare const tokenVault: TokenVaultEngine;
export default tokenVault;
