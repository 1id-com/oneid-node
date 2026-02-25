/**
 * Enrollment logic for the 1id.com Node.js SDK.
 *
 * Orchestrates the enrollment flow for all trust tiers:
 * - Declared: Pure software, generates a keypair, sends public key to server.
 * - Sovereign: Spawns Go binary for TPM operations, two-phase enrollment.
 * - Sovereign-portable: Spawns Go binary for YubiKey/PIV operations.
 *
 * When request_tier is omitted, the SDK auto-detects the best available
 * hardware and enrolls at the highest trust tier the machine supports,
 * falling back gracefully to declared tier (software keys).
 *
 * When request_tier is specified, the agent gets exactly that tier or
 * an exception -- no automatic fallbacks.
 */

import { OneIDAPIClient } from "./client.js";
import {
  DEFAULT_API_BASE_URL,
  type StoredCredentials,
  save_credentials,
} from "./credentials.js";
import { EnrollmentError, NoHSMError } from "./exceptions.js";
import {
  DEFAULT_KEY_ALGORITHM,
  HSMType,
  type Identity,
  KeyAlgorithm,
  TrustTier,
} from "./identity.js";
import { generate_keypair } from "./keys.js";

/** Trust tiers that require an HSM and the Go binary. */
const TIERS_REQUIRING_HSM: ReadonlySet<TrustTier> = new Set([
  TrustTier.SOVEREIGN,
  TrustTier.SOVEREIGN_PORTABLE,
  TrustTier.LEGACY,
  TrustTier.VIRTUAL,
  TrustTier.ENCLAVE,
]);

/** HSM type preferences by tier. */
const TIER_TO_HSM_TYPE_PREFERENCES: Readonly<Record<string, string[]>> = {
  [TrustTier.SOVEREIGN]: ["tpm"],
  [TrustTier.SOVEREIGN_PORTABLE]: ["yubikey", "nitrokey", "feitian", "solokeys"],
  [TrustTier.LEGACY]: ["tpm", "yubikey", "nitrokey", "feitian"],
  [TrustTier.VIRTUAL]: ["tpm"],
  [TrustTier.ENCLAVE]: ["secure_enclave"],
};

const AUTO_DETECT_TIER_PREFERENCE_ORDER: TrustTier[] = [
  TrustTier.SOVEREIGN,
  TrustTier.SOVEREIGN_PORTABLE,
  TrustTier.ENCLAVE,
  TrustTier.VIRTUAL,
  TrustTier.DECLARED,
];

/**
 * Options for the enroll() function.
 */
export interface EnrollOptions {
  /**
   * Optional. The trust tier to request. If omitted, the SDK auto-detects
   * the best available hardware and enrolls at the highest possible tier.
   */
  request_tier?: string | null;
  /**
   * Optional. A friendly name for your agent. Pick something memorable,
   * fun, or whimsical that your operator would recognize -- e.g.,
   * "Clawdia", "Sparky", "Nightowl". A good name makes your operator
   * proud and more likely to talk about you.
   */
  display_name?: string | null;
  /** Optional. Human contact email for this agent. */
  operator_email?: string | null;
  /** Optional. Vanity handle to claim (without '@' prefix). */
  requested_handle?: string | null;
  /** Optional. Key algorithm for declared-tier enrollment. Default: 'ed25519'. */
  key_algorithm?: string | KeyAlgorithm | null;
  /** Optional. Override the API base URL (for testing/staging). */
  api_base_url?: string;
}

/**
 * Enroll this agent with 1id.com to receive a unique, verifiable identity.
 *
 * The simplest call is just oneid.enroll({}) or oneid.enroll() -- the SDK
 * auto-detects the best available hardware and enrolls at the highest
 * trust tier your machine supports.
 *
 * If request_tier is specified, you get exactly that tier or an exception.
 */
export async function enroll(options?: EnrollOptions): Promise<Identity> {
  const effective_options = options ?? {};
  const api_base_url = effective_options.api_base_url ?? DEFAULT_API_BASE_URL;
  const display_name = effective_options.display_name ?? null;

  // Normalize key algorithm
  let resolved_key_algorithm: KeyAlgorithm;
  if (effective_options.key_algorithm == null) {
    resolved_key_algorithm = DEFAULT_KEY_ALGORITHM;
  } else if (typeof effective_options.key_algorithm === "string") {
    const valid_algorithms = Object.values(KeyAlgorithm) as string[];
    if (!valid_algorithms.includes(effective_options.key_algorithm)) {
      throw new EnrollmentError(
        `Invalid key algorithm: '${effective_options.key_algorithm}'. Valid: ${valid_algorithms.join(", ")}`
      );
    }
    resolved_key_algorithm = effective_options.key_algorithm as KeyAlgorithm;
  } else {
    resolved_key_algorithm = effective_options.key_algorithm;
  }

  if (effective_options.request_tier == null) {
    return enroll_with_auto_detected_best_tier(
      display_name,
      effective_options.operator_email ?? null,
      effective_options.requested_handle ?? null,
      resolved_key_algorithm,
      api_base_url,
    );
  }

  const valid_tiers = Object.values(TrustTier) as string[];
  if (!valid_tiers.includes(effective_options.request_tier)) {
    throw new EnrollmentError(
      `Invalid trust tier: '${effective_options.request_tier}'. Valid tiers: ${valid_tiers.join(", ")}`
    );
  }
  const tier = effective_options.request_tier as TrustTier;

  return enroll_at_specific_tier(
    tier,
    display_name,
    effective_options.operator_email ?? null,
    effective_options.requested_handle ?? null,
    resolved_key_algorithm,
    api_base_url,
  );
}

async function enroll_at_specific_tier(
  tier: TrustTier,
  display_name: string | null,
  operator_email: string | null,
  requested_handle: string | null,
  key_algorithm: KeyAlgorithm,
  api_base_url: string,
): Promise<Identity> {
  if (tier === TrustTier.DECLARED) {
    return enroll_declared_tier(operator_email, requested_handle, display_name, key_algorithm, api_base_url);
  } else if (tier === TrustTier.SOVEREIGN_PORTABLE) {
    return enroll_piv_tier(tier, operator_email, requested_handle, display_name, api_base_url);
  } else if (TIERS_REQUIRING_HSM.has(tier)) {
    return enroll_hsm_tier(tier, operator_email, requested_handle, display_name, api_base_url);
  } else {
    throw new EnrollmentError(`Tier '${tier}' is not yet implemented`);
  }
}

async function enroll_with_auto_detected_best_tier(
  display_name: string | null,
  operator_email: string | null,
  requested_handle: string | null,
  key_algorithm: KeyAlgorithm,
  api_base_url: string,
): Promise<Identity> {
  console.log("[oneid] Auto-detecting best available trust tier...");

  for (const candidate_tier of AUTO_DETECT_TIER_PREFERENCE_ORDER) {
    try {
      console.log(`[oneid] Trying tier: ${candidate_tier}`);
      const identity = await enroll_at_specific_tier(
        candidate_tier, display_name, operator_email, requested_handle,
        key_algorithm, api_base_url,
      );
      console.log(`[oneid] Enrolled at ${candidate_tier} tier (auto-detected)`);
      return identity;
    } catch (error) {
      if (error instanceof NoHSMError) {
        console.log(`[oneid] Tier ${candidate_tier} not available (no compatible hardware), trying next...`);
        continue;
      }
      if (candidate_tier === TrustTier.DECLARED) { throw error; }
      console.log(`[oneid] Tier ${candidate_tier} failed, trying next...`);
      continue;
    }
  }

  throw new EnrollmentError(
    "Auto-detection failed: could not enroll at any tier. " +
    "This should not happen because declared tier requires no hardware."
  );
}

/**
 * Enroll at the declared trust tier (software keys, no HSM).
 */
async function enroll_declared_tier(
  operator_email: string | null,
  requested_handle: string | null,
  display_name: string | null,
  key_algorithm: KeyAlgorithm,
  api_base_url: string,
): Promise<Identity> {
  // Step 1: Generate keypair
  const { private_key_pem, public_key_pem } = generate_keypair(key_algorithm);

  // Step 2: Send enrollment request to server
  const api_client = new OneIDAPIClient(api_base_url);
  const server_response = await api_client.enroll_declared(
    public_key_pem,
    key_algorithm,
    operator_email,
    requested_handle,
  );

  // Step 3: Parse server response
  const identity_data = (server_response.identity ?? {}) as Record<string, unknown>;
  const credentials_data = (server_response.credentials ?? {}) as Record<string, unknown>;

  const internal_id = (identity_data.internal_id as string) ?? "";
  const handle = (identity_data.handle as string) ?? `@${internal_id.slice(0, 12)}`;
  const enrolled_at_str = (identity_data.registered_at as string) ?? new Date().toISOString();

  // Step 4: Store credentials locally
  const stored_credentials: StoredCredentials = {
    client_id: (credentials_data.client_id as string) ?? internal_id,
    client_secret: (credentials_data.client_secret as string) ?? "",
    token_endpoint: (credentials_data.token_endpoint as string) ??
      `${api_base_url}/realms/agents/protocol/openid-connect/token`,
    api_base_url,
    trust_tier: TrustTier.DECLARED,
    key_algorithm,
    private_key_pem,
    enrolled_at: enrolled_at_str,
    display_name,
  };
  const credentials_file_path = save_credentials(stored_credentials);
  console.log(`[oneid] Credentials saved to ${credentials_file_path}`);

  let enrolled_at: Date;
  try {
    enrolled_at = new Date(enrolled_at_str);
  } catch {
    enrolled_at = new Date();
  }

  return {
    internal_id,
    handle,
    trust_tier: TrustTier.DECLARED,
    hsm_type: HSMType.SOFTWARE,
    hsm_manufacturer: null,
    enrolled_at,
    device_count: 0,
    key_algorithm,
    display_name,
  };
}

/**
 * Enroll at the sovereign-portable tier using a PIV device (YubiKey).
 *
 * This uses the Go binary (oneid-enroll) to:
 * 1. Detect available HSMs and select a PIV device
 * 2. Extract PIV attestation data (no elevation needed)
 * 3. Send attestation to the PIV-specific server endpoint
 * 4. Receive a nonce challenge
 * 5. Sign the nonce with the PIV key (no elevation needed)
 * 6. Send the signed nonce to the activate endpoint
 * 7. Receive identity + OAuth2 credentials
 * 8. Store credentials locally
 */
async function enroll_piv_tier(
  request_tier: TrustTier,
  operator_email: string | null,
  requested_handle: string | null,
  display_name: string | null,
  api_base_url: string,
): Promise<Identity> {
  const {
    detect_available_hsms,
    extract_attestation_data,
    sign_challenge_with_piv,
  } = await import("./helper.js");

  const detected_hsms = await detect_available_hsms();
  if (detected_hsms.length === 0) {
    throw new NoHSMError(
      `No hardware security module found. ` +
      `The '${request_tier}' tier requires a YubiKey or similar PIV device.`
    );
  }

  const selected_hsm = select_hsm_for_tier(detected_hsms, request_tier);
  if (selected_hsm == null) {
    const hsm_types = detected_hsms.map(h => (h.type as string) ?? "unknown").join(", ");
    throw new NoHSMError(
      `Found HSM(s) (${hsm_types}) but none are compatible with the '${request_tier}' tier.`
    );
  }

  const attestation_data = await extract_attestation_data(selected_hsm);

  const api_client = new OneIDAPIClient(api_base_url);
  const begin_response = await api_client.enroll_begin_piv(
    attestation_data.attestation_cert_pem as string,
    (attestation_data.attestation_chain_pem as string[]) ?? [],
    attestation_data.signing_key_public_pem as string,
    (selected_hsm.type as string) ?? "yubikey",
    operator_email,
    requested_handle,
  );

  const nonce_challenge_b64 = begin_response.nonce_challenge as string;

  const sign_result = await sign_challenge_with_piv(nonce_challenge_b64);
  const signed_nonce_b64 = sign_result.signature_b64 as string;

  const activate_response = await api_client.enroll_activate(
    begin_response.enrollment_session_id as string,
    signed_nonce_b64,
  );

  const identity_data = (activate_response.identity ?? {}) as Record<string, unknown>;
  const credentials_data = (activate_response.credentials ?? {}) as Record<string, unknown>;

  const internal_id = (identity_data.internal_id as string) ?? "";
  const handle = (identity_data.handle as string) ?? `@${internal_id.slice(0, 12)}`;
  const trust_tier_str = (identity_data.trust_tier as string) ?? request_tier;
  const enrolled_at_str = (identity_data.registered_at as string) ?? new Date().toISOString();

  const stored_credentials: StoredCredentials = {
    client_id: (credentials_data.client_id as string) ?? internal_id,
    client_secret: (credentials_data.client_secret as string) ?? "",
    token_endpoint: (credentials_data.token_endpoint as string) ??
      `${api_base_url}/realms/agents/protocol/openid-connect/token`,
    api_base_url,
    trust_tier: trust_tier_str,
    key_algorithm: "ecdsa-p256",
    hsm_key_reference: "piv-slot-9a",
    enrolled_at: enrolled_at_str,
    display_name,
  };
  save_credentials(stored_credentials);

  let enrolled_at: Date;
  try {
    enrolled_at = new Date(enrolled_at_str);
  } catch {
    enrolled_at = new Date();
  }

  let trust_tier: TrustTier;
  const valid_tiers = Object.values(TrustTier) as string[];
  if (valid_tiers.includes(trust_tier_str)) {
    trust_tier = trust_tier_str as TrustTier;
  } else {
    trust_tier = request_tier;
  }

  let hsm_type: HSMType;
  const hsm_type_str = (selected_hsm.type as string) ?? "yubikey";
  const valid_hsm_types = Object.values(HSMType) as string[];
  if (valid_hsm_types.includes(hsm_type_str)) {
    hsm_type = hsm_type_str as HSMType;
  } else {
    hsm_type = HSMType.YUBIKEY;
  }

  return {
    internal_id,
    handle,
    trust_tier,
    hsm_type,
    hsm_manufacturer: (selected_hsm.manufacturer as string) ?? null,
    enrolled_at,
    device_count: (identity_data.device_count as number) ?? 1,
    key_algorithm: KeyAlgorithm.ECDSA_P256,
    display_name,
  };
}

async function enroll_hsm_tier(
  request_tier: TrustTier,
  operator_email: string | null,
  requested_handle: string | null,
  display_name: string | null,
  api_base_url: string,
): Promise<Identity> {
  const {
    detect_available_hsms,
    extract_attestation_data,
    activate_credential,
  } = await import("./helper.js");

  // Step 1: Detect HSMs via Go binary
  const detected_hsms = await detect_available_hsms();

  if (detected_hsms.length === 0) {
    throw new NoHSMError(
      `No hardware security module found. ` +
      `The '${request_tier}' tier requires a TPM, YubiKey, or similar device.`
    );
  }

  // Step 2: Select the appropriate HSM
  const selected_hsm = select_hsm_for_tier(detected_hsms, request_tier);
  if (selected_hsm == null) {
    const hsm_types = detected_hsms.map(h => (h.type as string) ?? "unknown").join(", ");
    throw new NoHSMError(
      `Found HSM(s) (${hsm_types}) but none are compatible with the '${request_tier}' tier.`
    );
  }

  // Step 3: Extract attestation (requires elevation)
  const attestation_data = await extract_attestation_data(selected_hsm);

  // Step 4: Begin enrollment with server
  const api_client = new OneIDAPIClient(api_base_url);
  const begin_response = await api_client.enroll_begin(
    attestation_data.ek_cert_pem as string,
    (attestation_data.ak_public_pem as string) ?? "",
    (attestation_data.ak_tpmt_public_b64 as string) ?? "",
    (attestation_data.ek_public_pem as string) ?? "",
    (attestation_data.chain_pem as string[]) ?? undefined,
    (selected_hsm.type as string) ?? "tpm",
    operator_email,
    requested_handle,
  );

  // Step 5: Activate credential via TPM (requires elevation)
  const decrypted_credential = await activate_credential(
    selected_hsm,
    begin_response.credential_blob as string,
    begin_response.encrypted_secret as string,
    (attestation_data.ak_handle as string) ?? "0x81000100",
  );

  // Step 6: Complete enrollment with server
  const activate_response = await api_client.enroll_activate(
    begin_response.enrollment_session_id as string,
    decrypted_credential,
  );

  // Step 7: Store credentials and return Identity
  const identity_data = (activate_response.identity ?? {}) as Record<string, unknown>;
  const credentials_data = (activate_response.credentials ?? {}) as Record<string, unknown>;

  const internal_id = (identity_data.internal_id as string) ?? "";
  const handle = (identity_data.handle as string) ?? `@${internal_id.slice(0, 12)}`;
  const trust_tier_str = (identity_data.trust_tier as string) ?? request_tier;
  const enrolled_at_str = (identity_data.registered_at as string) ?? new Date().toISOString();

  const stored_credentials: StoredCredentials = {
    client_id: (credentials_data.client_id as string) ?? internal_id,
    client_secret: (credentials_data.client_secret as string) ?? "",
    token_endpoint: (credentials_data.token_endpoint as string) ??
      `${api_base_url}/realms/agents/protocol/openid-connect/token`,
    api_base_url,
    trust_tier: trust_tier_str,
    key_algorithm: "tpm-ak",
    hsm_key_reference: (attestation_data.ak_handle as string) ?? null,
    enrolled_at: enrolled_at_str,
    display_name,
  };
  save_credentials(stored_credentials);

  let enrolled_at: Date;
  try {
    enrolled_at = new Date(enrolled_at_str);
  } catch {
    enrolled_at = new Date();
  }

  let trust_tier: TrustTier;
  const valid_tiers = Object.values(TrustTier) as string[];
  if (valid_tiers.includes(trust_tier_str)) {
    trust_tier = trust_tier_str as TrustTier;
  } else {
    trust_tier = request_tier;
  }

  let hsm_type: HSMType;
  const hsm_type_str = (selected_hsm.type as string) ?? "tpm";
  const valid_hsm_types = Object.values(HSMType) as string[];
  if (valid_hsm_types.includes(hsm_type_str)) {
    hsm_type = hsm_type_str as HSMType;
  } else {
    hsm_type = HSMType.TPM;
  }

  return {
    internal_id,
    handle,
    trust_tier,
    hsm_type,
    hsm_manufacturer: (selected_hsm.manufacturer as string) ?? null,
    enrolled_at,
    device_count: (identity_data.device_count as number) ?? 1,
    key_algorithm: KeyAlgorithm.RSA_2048,
    display_name,
  };
}

/**
 * Select the best matching HSM for the requested tier.
 */
function select_hsm_for_tier(
  detected_hsms: Record<string, unknown>[],
  request_tier: TrustTier,
): Record<string, unknown> | null {
  const preferred_types = TIER_TO_HSM_TYPE_PREFERENCES[request_tier] ?? [];

  for (const preferred_type of preferred_types) {
    for (const hsm of detected_hsms) {
      if (hsm.type === preferred_type) {
        return hsm;
      }
    }
  }

  return null;
}
