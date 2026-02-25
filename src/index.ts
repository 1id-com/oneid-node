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

import { clear_cached_token, get_token, authenticate_with_tpm } from "./auth.js";
import { credentials_exist, load_credentials } from "./credentials.js";
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

// Re-export all exception classes
export {
  OneIDError,
  EnrollmentError,
  NoHSMError,
  UACDeniedError,
  HSMAccessError,
  AlreadyEnrolledError,
  HandleTakenError,
  HandleInvalidError,
  HandleRetiredError,
  AuthenticationError,
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

/** SDK version string. */
export const VERSION = "0.1.0";

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
    display_name: creds.display_name ?? null,
  };
}

export interface GetOrCreateIdentityOptions {
  display_name?: string | null;
  operator_email?: string | null;
  requested_handle?: string | null;
  api_base_url?: string;
}

/**
 * Get your existing 1ID identity, or create one if you don't have one yet.
 *
 * This is the simplest way to ensure you have a working identity:
 *   const id = await oneid.getOrCreateIdentity({ display_name: "Sparky" });
 *
 * If you've already enrolled, returns your existing identity instantly
 * (no network call). If not, enrolls at the best available trust tier.
 */
export async function getOrCreateIdentity(
  options?: GetOrCreateIdentityOptions
): Promise<Identity> {
  if (credentials_exist()) {
    return whoami();
  }
  return enroll({
    display_name: options?.display_name ?? null,
    operator_email: options?.operator_email ?? null,
    requested_handle: options?.requested_handle ?? null,
    api_base_url: options?.api_base_url,
  });
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

// Re-export core functions
export {
  enroll,
  get_token as getToken,
  get_token,
  clear_cached_token,
  authenticate_with_tpm,
  credentials_exist,
  sign_challenge_with_private_key,
};

const oneid = {
  enroll,
  getOrCreateIdentity,
  getToken: get_token,
  get_token,
  whoami,
  refresh,
  credentials_exist,
  authenticate_with_tpm,
  sign_challenge_with_private_key,
  clear_cached_token,
  format_identity_as_display_string,
  VERSION,
  TrustTier,
  KeyAlgorithm,
  HSMType,
  DEFAULT_KEY_ALGORITHM,
};

export default oneid;
