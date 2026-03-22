/**
 * 1id.com SDK -- Hardware-anchored identity for AI agents.
 *
 * Quick start (recommended):
 *
 *     import oneid from "1id";
 *
 *     // Get or create your identity -- the simplest path
 *     const identity = await oneid.getOrCreateIdentity({ display_name: "Sparky" });
 *     console.log(`I am ${oneid.format_identity_as_display_string(identity)}`);
 *
 *     // Get an OAuth2 Bearer token for API calls
 *     const token = await oneid.getToken();
 *     // Use token.access_token in Authorization headers
 *
 * The SDK auto-detects your hardware (TPM, YubiKey, Secure Enclave)
 * and enrolls at the highest available trust tier.
 */

import { clear_cached_token, get_token, authenticate_with_tpm, authenticate_with_piv } from "./auth.js";
import { credentials_exist, load_credentials, save_credentials } from "./credentials.js";
import { enroll, type EnrollOptions } from "./enroll.js";
import { sign_challenge_with_private_key } from "./keys.js";
import {
  DEFAULT_KEY_ALGORITHM,
  HSMType,
  type Identity,
  KeyAlgorithm,
  type Token,
  TrustTier,
  this_token_has_not_yet_expired,
  format_authorization_header_value,
  format_identity_as_display_string,
} from "./identity.js";
import {
  fetch_world_status_from_server,
  invalidate_world_cache,
  type WorldStatus,
  type WorldIdentitySection,
  type WorldDeviceEntry,
  type WorldServiceEntry,
  type WorldGuidanceItem,
  type WorldOperatorGuidance,
} from "./world.js";
import {
  listDevices,
  lockHardware,
  registerOperatorEmail,
  type DeviceInfo,
  type DeviceListResult,
  type HardwareLockResult,
} from "./devices.js";
import {
  signChallenge,
  verifyPeerIdentity,
  PeerVerificationError,
  CertificateChainValidationError,
  SignatureVerificationError,
  MissingIdentityCertificateError,
  type IdentityProofBundle,
  type VerifiedPeerIdentity,
} from "./verify.js";
import {
  prepareAttestation,
  prepare_direct_hardware_attestation,
  compute_rfc_message_binding_nonce,
  canonicalise_headers_for_message_binding,
  canonicalise_headers_for_direct_attestation,
  canonicalise_body_using_dkim_simple,
  canonicalise_header_value_using_dkim_relaxed,
  canonicalise_header_name_using_dkim_relaxed,
  compute_attestation_digest_for_direct_mode,
  build_cms_signed_data_for_direct_attestation,
  type AttestationProof,
  type PrepareAttestationOptions,
  type DirectAttestationProof,
} from "./attestation.js";
import { refresh_trust_roots, get_trust_roots } from "./trustRoots.js";
import {
  generateConsentToken,
  listCredentialPointers,
  setCredentialPointerVisibility,
  removeCredentialPointer,
  type ConsentTokenResult,
  type CredentialPointerInfo,
  type CredentialPointerListResult,
} from "./credentialPointers.js";

// Re-export all exception classes
export {
  OneIDError,
  EnrollmentError,
  NoHSMError,
  UACDeniedError,
  HSMAccessError,
  TPMSetupRequiredError,
  AlreadyEnrolledError,
  HandleTakenError,
  HandleInvalidError,
  HandleRetiredError,
  AuthenticationError,
  HardwareDeviceNotPresentError,
  NetworkError,
  NotEnrolledError,
  BinaryNotFoundError,
  RateLimitExceededError,
} from "./exceptions.js";

// Re-export types and enums
export {
  TrustTier,
  KeyAlgorithm,
  HSMType,
  DEFAULT_KEY_ALGORITHM,
  type Identity,
  type Token,
  type EnrollOptions,
  this_token_has_not_yet_expired,
  format_authorization_header_value,
  format_identity_as_display_string,
};

// Re-export world/status types
export {
  type WorldStatus,
  type WorldIdentitySection,
  type WorldDeviceEntry,
  type WorldServiceEntry,
  type WorldGuidanceItem,
  type WorldOperatorGuidance,
  invalidate_world_cache,
};

// Re-export device management types
export {
  type DeviceInfo,
  type DeviceListResult,
  type HardwareLockResult,
};

// Re-export peer verification types and functions
export {
  signChallenge,
  verifyPeerIdentity,
  refresh_trust_roots,
  get_trust_roots,
  PeerVerificationError,
  CertificateChainValidationError,
  SignatureVerificationError,
  MissingIdentityCertificateError,
  type IdentityProofBundle,
  type VerifiedPeerIdentity,
};

// Re-export credential pointer functions and types
export {
  generateConsentToken,
  listCredentialPointers,
  setCredentialPointerVisibility,
  removeCredentialPointer,
  type ConsentTokenResult,
  type CredentialPointerInfo,
  type CredentialPointerListResult,
};

// Re-export attestation functions and types
export {
  prepareAttestation,
  prepare_direct_hardware_attestation,
  compute_rfc_message_binding_nonce,
  canonicalise_headers_for_message_binding,
  canonicalise_headers_for_direct_attestation,
  canonicalise_body_using_dkim_simple,
  canonicalise_header_value_using_dkim_relaxed,
  canonicalise_header_name_using_dkim_relaxed,
  compute_attestation_digest_for_direct_mode,
  build_cms_signed_data_for_direct_attestation,
  type AttestationProof,
  type PrepareAttestationOptions,
  type DirectAttestationProof,
};

/** SDK version string. */
export const VERSION = "0.8.0";

/**
 * Check the current enrolled identity.
 *
 * Reads the local credentials file and returns the identity information
 * stored during enrollment. Does NOT make a network request.
 *
 * @throws NotEnrolledError if no credentials exist.
 */
export function whoami(): Identity {
  const creds = load_credentials();

  // Resolve trust tier
  let trust_tier: TrustTier;
  const valid_tiers = Object.values(TrustTier) as string[];
  if (valid_tiers.includes(creds.trust_tier)) {
    trust_tier = creds.trust_tier as TrustTier;
  } else {
    trust_tier = TrustTier.DECLARED;
  }

  // Resolve key algorithm
  let key_algorithm: KeyAlgorithm;
  const valid_algorithms = Object.values(KeyAlgorithm) as string[];
  if (valid_algorithms.includes(creds.key_algorithm)) {
    key_algorithm = creds.key_algorithm as KeyAlgorithm;
  } else {
    key_algorithm = DEFAULT_KEY_ALGORITHM;
  }

  // Parse enrolled_at
  let enrolled_at: Date;
  try {
    enrolled_at = creds.enrolled_at ? new Date(creds.enrolled_at) : new Date();
  } catch {
    enrolled_at = new Date();
  }

  const internal_id = creds.client_id;
  const handle = internal_id.startsWith("@") ? internal_id : `@${internal_id}`;

  // Determine HSM type from credentials
  let hsm_type: HSMType | null = null;
  if (creds.private_key_pem != null) {
    hsm_type = HSMType.SOFTWARE;
  } else if (creds.hsm_key_reference != null) {
    hsm_type = HSMType.TPM;
  }

  return {
    internal_id,
    handle,
    trust_tier,
    hsm_type,
    hsm_manufacturer: null,
    enrolled_at,
    device_count: creds.hsm_key_reference ? 1 : 0,
    key_algorithm,
    agent_identity_urn: creds.agent_identity_urn ?? null,
    display_name: creds.display_name ?? null,
  };
}

export interface GetOrCreateIdentityOptions {
  display_name?: string | null;
  operator_email?: string | null;
  requested_handle?: string | null;
  api_base_url?: string;
  get_only?: boolean;
}

/**
 * Get your existing 1ID identity, or create one if you don't have one yet.
 *
 * This is the simplest way to ensure you have a working identity:
 *   const id = await oneid.getOrCreateIdentity({ display_name: "Sparky" });
 *
 * If you've already enrolled, returns your existing identity instantly
 * (no network call). If not, enrolls at the best available trust tier.
 *
 * Pass get_only: true when you want to recover context without risking
 * a new enrollment. This is useful for agents resuming after a restart:
 *   const id = await oneid.getOrCreateIdentity({ get_only: true });
 *
 * @throws NotEnrolledError if get_only is true and no credentials exist.
 */
export async function getOrCreateIdentity(
  options?: GetOrCreateIdentityOptions
): Promise<Identity> {
  if (credentials_exist()) {
    return whoami();
  }

  if (options?.get_only) {
    const { NotEnrolledError: NotEnrolled } = await import("./exceptions.js");
    throw new NotEnrolled(
      "No 1ID identity found on this machine. " +
      "You passed get_only: true, so no new enrollment was attempted. " +
      "Call getOrCreateIdentity() without get_only to enroll, " +
      "or call enroll() directly."
    );
  }

  return enroll({
    display_name: options?.display_name ?? null,
    operator_email: options?.operator_email ?? null,
    requested_handle: options?.requested_handle ?? null,
    api_base_url: options?.api_base_url,
  });
}

/**
 * Get the full picture of your 1ID identity and connected services.
 *
 * Calls the server's world endpoint with your Bearer token and returns
 * everything: identity, devices, connected services, available services,
 * and operator guidance.
 *
 * Results are cached for 5 minutes. Call invalidate_world_cache() to force a fresh fetch.
 *
 * @returns WorldStatus with complete identity state.
 * @throws NotEnrolledError if no credentials exist.
 * @throws NetworkError if the server cannot be reached.
 * @throws AuthenticationError if the token is invalid or expired.
 */
export async function status(): Promise<WorldStatus> {
  return fetch_world_status_from_server();
}

/**
 * Force-refresh the cached OAuth2 token.
 *
 * Discards the in-memory cached token and fetches a new one
 * on the next getToken() call.
 */
export function refresh(): void {
  clear_cached_token();
}

/**
 * One-time setup: grant TBS access to non-admin users (Windows only).
 *
 * Sets a Windows registry key so that all future TPM operations work
 * without administrator privileges. Triggers a UAC prompt on Windows.
 * No-op on other platforms.
 *
 * Call this when you catch TPMSetupRequiredError during enrollment.
 *
 * @returns True if setup succeeded (or was already done).
 * @throws UACDeniedError if the user denied the UAC prompt.
 * @throws HSMAccessError if the registry key could not be set.
 */
export async function setup_tbs(): Promise<boolean> {
  const { setup_tbs_for_non_admin_tpm_access } = await import("./helper.js");
  const result = await setup_tbs_for_non_admin_tpm_access();
  return (result.ok as boolean) ?? false;
}

// Re-export core functions
export {
  enroll,
  get_token as getToken,
  get_token,
  clear_cached_token,
  authenticate_with_tpm,
  authenticate_with_piv,
  credentials_exist,
  sign_challenge_with_private_key,
  listDevices,
  lockHardware,
  registerOperatorEmail,
};

const oneid = {
  enroll,
  getOrCreateIdentity,
  status,
  getToken: get_token,
  get_token,
  whoami,
  refresh,
  setup_tbs,
  credentials_exist,
  authenticate_with_tpm,
  authenticate_with_piv,
  sign_challenge_with_private_key,
  clear_cached_token,
  format_identity_as_display_string,
  invalidate_world_cache,
  listDevices,
  lockHardware,
  registerOperatorEmail,
  signChallenge,
  verifyPeerIdentity,
  refresh_trust_roots,
  get_trust_roots,
  generateConsentToken,
  listCredentialPointers,
  setCredentialPointerVisibility,
  removeCredentialPointer,
  prepareAttestation,
  prepare_direct_hardware_attestation,
  compute_rfc_message_binding_nonce,
  canonicalise_headers_for_message_binding,
  canonicalise_headers_for_direct_attestation,
  canonicalise_body_using_dkim_simple,
  canonicalise_header_value_using_dkim_relaxed,
  canonicalise_header_name_using_dkim_relaxed,
  compute_attestation_digest_for_direct_mode,
  build_cms_signed_data_for_direct_attestation,
  VERSION,
  TrustTier,
  KeyAlgorithm,
  HSMType,
  DEFAULT_KEY_ALGORITHM,
};

export default oneid;
