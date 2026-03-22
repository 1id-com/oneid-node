/**
 * Identity and Token data models for the 1id.com Node.js SDK.
 *
 * These types represent the agent's enrolled identity and OAuth2 tokens.
 * They are returned by enroll(), whoami(), and getToken() respectively.
 */

/**
 * Trust tiers assigned by 1id.com based on hardware attestation.
 *
 * RFC: draft-drake-email-hardware-attestation-00 Section 3.
 *
 * Ordered from highest to lowest Sybil resistance:
 * - sovereign (TPM): Non-portable discrete/firmware TPM, manufacturer CA chain verifiable
 * - portable  (PIV): Portable PIV device (YubiKey/Nitrokey/Feitian), manufacturer-attested
 * - enclave   (ENC): Apple Secure Enclave (CryptoKit), hardware-backed but not Sybil-resistant
 * - virtual   (VRT): Hypervisor vTPM (VMware/Hyper-V/QEMU), hypervisor-attested
 * - declared  (SFT): Software-only, no hardware proof, works everywhere
 */
export enum TrustTier {
  SOVEREIGN = "sovereign",
  PORTABLE = "portable",
  ENCLAVE = "enclave",
  VIRTUAL = "virtual",
  DECLARED = "declared",
}

/**
 * Supported key algorithms for declared-tier software keys.
 */
export enum KeyAlgorithm {
  ED25519 = "ed25519",
  ECDSA_P256 = "ecdsa-p256",
  ECDSA_P384 = "ecdsa-p384",
  RSA_2048 = "rsa-2048",
  RSA_4096 = "rsa-4096",
}

/** The default key algorithm for declared-tier enrollment. */
export const DEFAULT_KEY_ALGORITHM = KeyAlgorithm.ED25519;

/**
 * Types of hardware security modules supported by 1id.com.
 */
export enum HSMType {
  TPM = "tpm",
  YUBIKEY = "yubikey",
  NITROKEY = "nitrokey",
  FEITIAN = "feitian",
  SOLOKEYS = "solokeys",
  SECURE_ENCLAVE = "secure_enclave",
  SOFTWARE = "software",
}

/**
 * Represents an enrolled 1id.com agent identity.
 *
 * Returned by enroll() and whoami(). All fields are readonly.
 */
export interface Identity {
  /** Permanent unique identifier (e.g., '1id-a7b3c9d2'). Never changes. */
  readonly internal_id: string;
  /** Handle (e.g., '@clawdia' or '@1id-a7b3c9d2'). */
  readonly handle: string;
  /** The trust level assigned based on hardware attestation. */
  readonly trust_tier: TrustTier;
  /** Type of HSM used for enrollment, or null for declared tier. */
  readonly hsm_type: HSMType | null;
  /** Manufacturer code (e.g., 'INTC', 'Yubico'), or null. */
  readonly hsm_manufacturer: string | null;
  /** When this identity was first created. */
  readonly enrolled_at: Date;
  /** Number of HSMs currently linked to this identity. */
  readonly device_count: number;
  /** The key algorithm used for this identity's signing key. */
  readonly key_algorithm: KeyAlgorithm;
  /** Agent Identity URN (e.g., 'urn:aid:1id.com:1id-a7b3c9d2'), or null if not yet assigned. */
  readonly agent_identity_urn: string | null;
  /** Friendly name chosen by the agent (e.g., "Clawdia", "Sparky"). */
  readonly display_name: string | null;
}

/**
 * Represents an OAuth2 access token from 1id.com / Keycloak.
 *
 * Returned by getToken(). The accessToken is a signed JWT
 * containing the agent's identity claims (sub, handle, trust_tier, etc.).
 */
export interface Token {
  /** The JWT access token string (Bearer token). */
  readonly access_token: string;
  /** Always 'Bearer'. */
  readonly token_type: string;
  /** When this token expires (UTC). */
  readonly expires_at: Date;
  /** Refresh token for obtaining new access tokens, or null. */
  readonly refresh_token: string | null;
}

/**
 * Check whether a token is still valid based on its expiry time.
 *
 * Returns true if the token's expiry time is in the future.
 * Does NOT verify the JWT signature or check revocation.
 */
export function this_token_has_not_yet_expired(token: Token): boolean {
  return new Date() < token.expires_at;
}

/**
 * Format a token for use in an HTTP Authorization header.
 *
 * Returns a string in the format 'Bearer <access_token>'.
 */
export function format_authorization_header_value(token: Token): string {
  return `${token.token_type} ${token.access_token}`;
}

/**
 * Format an Identity as a human-readable string.
 */
export function format_identity_as_display_string(identity: Identity): string {
  const name_part = identity.display_name ? ` (${identity.display_name})` : "";
  const urn_part = identity.agent_identity_urn ? `, urn: ${identity.agent_identity_urn}` : "";
  return `${identity.handle}${name_part} (tier: ${identity.trust_tier}, id: ${identity.internal_id}${urn_part})`;
}
