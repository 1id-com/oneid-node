/**
 * Device management for the 1id.com Node.js SDK.
 *
 * Provides:
 *   listDevices()          -- List all devices (active and burned) bound to this identity
 *   addDevice()            -- Add a hardware device (declared->hardware upgrade or co-location)
 *   burnDevice()           -- Permanently retire a device (two-step with co-device signature)
 *   requestBurn()          -- Step 1: request burn confirmation token
 *   confirmBurn()          -- Step 2: confirm burn with co-device signature
 *   lockHardware()         -- Permanently lock identity to its single device (irreversible)
 *   registerOperatorEmail() -- Register operator contact email
 */

import { load_credentials, save_credentials, type StoredCredentials } from "./credentials.js";
import { get_token } from "./auth.js";
import { OneIDAPIClient } from "./client.js";
import { OneIDError } from "./exceptions.js";
import { invalidate_world_cache } from "./world.js";

export interface DeviceInfo {
  device_type: string;
  device_fingerprint: string;
  device_status: string;
  trust_tier: string | null;
  tpm_manufacturer: string | null;
  piv_serial: string | null;
  bound_at: string | null;
  burned_at: string | null;
  burn_reason: string | null;
}

export interface DeviceListResult {
  identity_internal_id: string;
  total_device_count: number;
  active_device_count: number;
  burned_device_count: number;
  devices: DeviceInfo[];
}

export interface HardwareLockResult {
  identity_internal_id: string;
  hardware_locked: boolean;
  trust_tier: string;
  active_device_count: number;
}

export interface DeviceAddResult {
  device_type: string;
  device_fingerprint: string;
  trust_tier: string;
  identity_was_upgraded_from_declared: boolean;
  previous_tier: string | null;
  device_serial: string | null;
}

export interface BurnRequestResult {
  token_id: string;
  expires_at: string;
  target_device_fingerprint: string;
  target_device_type: string;
  active_devices_remaining_after_burn: number;
}

export interface BurnConfirmResult {
  burned_device_fingerprint: string;
  burned_device_type: string;
  burn_reason: string | null;
  confirmed_by_device_fingerprint: string;
  confirmed_by_device_type: string;
  remaining_active_devices: number;
  new_trust_tier: string | null;
}

export class DeviceManagementError extends OneIDError {
  constructor(message: string, error_code?: string) {
    super(message, error_code ?? "DEVICE_MANAGEMENT_ERROR");
    this.name = "DeviceManagementError";
  }
}

function _raise_from_device_api_error_code(response_data: Record<string, unknown>): void {
  if (response_data.ok) { return; }
  const error_info = (response_data.error ?? {}) as Record<string, unknown>;
  const error_code = (error_info.code ?? "UNKNOWN") as string;
  const error_message = (error_info.message ?? "Device management operation failed") as string;
  throw new DeviceManagementError(error_message, error_code);
}

/**
 * List all devices (active and burned) bound to this identity.
 *
 * @param credentials Optional pre-loaded credentials.
 * @returns DeviceListResult with all device details.
 */
export async function listDevices(
  credentials?: StoredCredentials | null,
): Promise<DeviceListResult> {
  if (credentials == null) {
    credentials = load_credentials();
  }

  const token = await get_token(false, credentials);
  const api_client = new OneIDAPIClient(credentials.api_base_url);

  const response_data = await api_client.make_authenticated_request(
    "GET",
    "/api/v1/identity/devices",
    token.access_token,
  );

  const raw_devices = (response_data.devices ?? []) as Record<string, unknown>[];

  return {
    identity_internal_id: (response_data.identity_internal_id ?? "") as string,
    total_device_count: (response_data.total_devices ?? 0) as number,
    active_device_count: (response_data.active_devices ?? 0) as number,
    burned_device_count: (response_data.burned_devices ?? 0) as number,
    devices: raw_devices.map((device_data) => ({
      device_type: (device_data.device_type ?? "") as string,
      device_fingerprint: (device_data.device_fingerprint ?? "") as string,
      device_status: (device_data.device_status ?? "active") as string,
      trust_tier: (device_data.trust_tier ?? null) as string | null,
      tpm_manufacturer: (device_data.tpm_manufacturer ?? null) as string | null,
      piv_serial: (device_data.piv_serial ?? null) as string | null,
      bound_at: (device_data.bound_at ?? null) as string | null,
      burned_at: (device_data.burned_at ?? null) as string | null,
      burn_reason: (device_data.burn_reason ?? null) as string | null,
    })),
  };
}

/**
 * Permanently lock this identity to its single active hardware device.
 *
 * This is an IRREVERSIBLE operation. Once locked:
 *   - No new devices can be added
 *   - The existing device cannot be burned
 *   - The identity is permanently bound to one physical chip
 *
 * Preconditions enforced server-side:
 *   - Identity must be hardware-tier (sovereign, portable, or virtual)
 *   - Identity must have exactly 1 active device
 *
 * @param credentials Optional pre-loaded credentials.
 * @returns HardwareLockResult with confirmation details.
 * @throws Error with code DECLARED_TIER_CANNOT_LOCK if identity is declared-tier.
 * @throws Error with code ALREADY_LOCKED if already locked (idempotent-safe).
 * @throws Error with code TOO_MANY_ACTIVE_DEVICES if identity has != 1 active device.
 */
export async function lockHardware(
  credentials?: StoredCredentials | null,
): Promise<HardwareLockResult> {
  if (credentials == null) {
    credentials = load_credentials();
  }

  const token = await get_token(false, credentials);
  const api_client = new OneIDAPIClient(credentials.api_base_url);

  const lock_data = await api_client.make_authenticated_request(
    "POST",
    "/api/v1/identity/lock-hardware",
    token.access_token,
    {},
  );

  invalidate_world_cache();

  return {
    identity_internal_id: (lock_data.identity_internal_id ?? "") as string,
    hardware_locked: Boolean(lock_data.hardware_locked),
    trust_tier: (lock_data.trust_tier ?? "") as string,
    active_device_count: (lock_data.active_device_count ?? 1) as number,
  };
}

/**
 * Add a new hardware device to this identity.
 *
 * Two code paths, automatically selected based on identity state:
 *   1. Declared -> hardware upgrade (no co-location): detects TPM/YubiKey,
 *      extracts attestation, sends to server, upgrades tier, updates credentials.
 *   2. Hardware -> hardware (co-location binding): orchestrates the 042.3
 *      co-location ceremony (requires existing_device_fingerprint/type).
 *
 * @param device_type Optional 'tpm' or 'piv'. Auto-detects if omitted.
 * @param existing_device_fingerprint For hardware-to-hardware additions only.
 * @param existing_device_type For hardware-to-hardware additions only ('tpm' or 'piv').
 * @param credentials Optional pre-loaded credentials.
 */
export async function addDevice(
  device_type?: string | null,
  existing_device_fingerprint?: string | null,
  existing_device_type?: string | null,
  credentials?: StoredCredentials | null,
): Promise<DeviceAddResult> {
  if (credentials == null) {
    credentials = load_credentials();
  }

  const current_tier = credentials.trust_tier;

  if (current_tier === "declared" || !credentials.hsm_key_reference) {
    return _add_device_via_declared_to_hardware_upgrade(device_type ?? null, credentials);
  }

  if (!existing_device_fingerprint || !existing_device_type) {
    throw new DeviceManagementError(
      "This identity already has hardware devices. To add another device, " +
      "you must provide existing_device_fingerprint and existing_device_type " +
      "for the co-location binding ceremony. Use listDevices() to see current devices.",
      "COLOCATION_REQUIRED",
    );
  }

  return _add_device_via_colocation_binding(
    existing_device_fingerprint,
    existing_device_type,
    device_type ?? "piv",
    credentials,
  );
}


async function _add_device_via_declared_to_hardware_upgrade(
  device_type_preference: string | null,
  credentials: StoredCredentials,
): Promise<DeviceAddResult> {
  const { detect_available_hsms, extract_attestation_data } = await import("./helper.js");

  const detected_hsms = await detect_available_hsms();
  if (!detected_hsms || detected_hsms.length === 0) {
    throw new DeviceManagementError(
      "No hardware security module found. Device addition requires a TPM, YubiKey, or similar device.",
      "NO_HSM",
    );
  }

  let selected_hsm: Record<string, unknown> | null = null;
  if (device_type_preference) {
    for (const hsm of detected_hsms) {
      if (hsm.type === device_type_preference || (device_type_preference === "piv" && (hsm.type === "yubikey" || hsm.type === "piv"))) {
        selected_hsm = hsm;
        break;
      }
    }
    if (!selected_hsm) {
      throw new DeviceManagementError(`No ${device_type_preference} device found.`, "NO_HSM");
    }
  } else {
    for (const hsm of detected_hsms) {
      if (hsm.type === "tpm") { selected_hsm = hsm; break; }
    }
    if (!selected_hsm) {
      for (const hsm of detected_hsms) {
        if (hsm.type === "yubikey" || hsm.type === "piv") { selected_hsm = hsm; break; }
      }
    }
    if (!selected_hsm) {
      throw new DeviceManagementError("Found HSM(s) but none are compatible for device addition.", "NO_HSM");
    }
  }

  const attestation_data = await extract_attestation_data(selected_hsm);
  const hsm_type = (selected_hsm.type ?? "tpm") as string;

  let request_body: Record<string, unknown>;
  let new_hsm_key_reference: string;
  let new_key_algorithm: string;

  if (hsm_type === "yubikey" || hsm_type === "piv") {
    request_body = {
      device_type: "piv",
      attestation_cert_pem: attestation_data.attestation_cert_pem ?? attestation_data.ek_cert_pem ?? "",
      attestation_chain_pem: attestation_data.attestation_chain_pem ?? attestation_data.chain_pem ?? [],
      signing_key_public_pem: attestation_data.signing_key_public_pem ?? attestation_data.ak_public_pem ?? "",
    };
    new_hsm_key_reference = "piv-slot-9a";
    new_key_algorithm = "ecdsa-p256";
  } else {
    request_body = {
      device_type: "tpm",
      ek_certificate_pem: attestation_data.ek_cert_pem ?? "",
      ak_public_key_pem: attestation_data.ak_public_pem ?? "",
      ak_tpmt_public_b64: attestation_data.ak_tpmt_public_b64 ?? "",
      ek_public_key_pem: attestation_data.ek_public_pem ?? "",
      ek_certificate_chain_pem: attestation_data.chain_pem ?? [],
    };
    new_hsm_key_reference = (attestation_data.ak_handle as string) ?? "transient";
    new_key_algorithm = "tpm-ak";
  }

  const token = await get_token(false, credentials);
  const api_client = new OneIDAPIClient(credentials.api_base_url);
  const response_data = await api_client.make_authenticated_request(
    "POST", "/api/v1/identity/devices/add", token.access_token, request_body,
  );
  _raise_from_device_api_error_code(response_data);

  const new_tier = (response_data.trust_tier ?? (hsm_type === "tpm" ? "sovereign" : "portable")) as string;
  const identity_was_upgraded = Boolean(response_data.identity_upgraded);

  if (identity_was_upgraded) {
    const updated_credentials: StoredCredentials = {
      ...credentials,
      trust_tier: new_tier,
      key_algorithm: new_key_algorithm,
      private_key_pem: undefined,
      hsm_key_reference: new_hsm_key_reference,
    };
    save_credentials(updated_credentials);
  }

  invalidate_world_cache();

  return {
    device_type: (response_data.device_type ?? request_body.device_type) as string,
    device_fingerprint: (response_data.device_fingerprint ?? "") as string,
    trust_tier: new_tier,
    identity_was_upgraded_from_declared: identity_was_upgraded,
    previous_tier: (response_data.previous_tier ?? null) as string | null,
    device_serial: (response_data.device_serial ?? null) as string | null,
  };
}


async function _add_device_via_colocation_binding(
  existing_device_fingerprint: string,
  existing_device_type: string,
  new_device_type: string,
  credentials: StoredCredentials,
): Promise<DeviceAddResult> {
  const { run_binary_command, detect_available_hsms, extract_attestation_data } = await import("./helper.js");

  const token = await get_token(false, credentials);
  const api_client = new OneIDAPIClient(credentials.api_base_url);

  const session_data = await api_client.make_authenticated_request(
    "POST", "/api/v1/identity/piv-bind/begin", token.access_token, {
      existing_device_fingerprint,
      existing_device_type,
      new_device_type,
    },
  );

  const session_id = session_data.session_id as string;
  const server_nonce_b64 = session_data.server_nonce_b64 as string;

  const ceremony_result = await run_binary_command("piv-bind-ceremony", [
    "--nonce", server_nonce_b64,
    "--session-id", session_id,
    "--elevated",
  ]);

  const c1_quote_data = ceremony_result.c1_quote as Record<string, unknown>;
  const c2_quote_data = ceremony_result.c2_quote as Record<string, unknown>;
  const s2_signature_b64 = ceremony_result.s2_signature_b64 as string;

  const detected_hsms = await detect_available_hsms();
  let piv_hsm: Record<string, unknown> | null = null;
  for (const hsm of detected_hsms) {
    if (hsm.type === "yubikey" || hsm.type === "piv") { piv_hsm = hsm; break; }
  }
  if (!piv_hsm) {
    throw new DeviceManagementError("No PIV device found for attestation extraction", "COLOCATION_FAILED");
  }

  const piv_attestation = await extract_attestation_data(piv_hsm);

  const complete_data = await api_client.make_authenticated_request(
    "POST", "/api/v1/identity/piv-bind/complete", token.access_token, {
      session_id,
      c1_quote: c1_quote_data,
      s2_signature_b64,
      c2_quote: c2_quote_data,
      new_device_attestation: {
        attestation_cert_pem: piv_attestation.attestation_cert_pem ?? piv_attestation.ek_cert_pem ?? "",
        chain_pem: piv_attestation.attestation_chain_pem ?? piv_attestation.chain_pem ?? [],
        signing_key_public_pem: piv_attestation.signing_key_public_pem ?? piv_attestation.ak_public_pem ?? "",
        serial: piv_attestation.serial_number ?? piv_attestation.serial ?? "",
      },
    },
  );

  invalidate_world_cache();

  return {
    device_type: "piv",
    device_fingerprint: (complete_data.new_device_fingerprint ?? "") as string,
    trust_tier: "portable",
    identity_was_upgraded_from_declared: false,
    previous_tier: null,
    device_serial: (complete_data.new_device_serial ?? null) as string | null,
  };
}


/**
 * Permanently retire (burn) a device from this identity.
 *
 * Two-step process: requests a burn token, signs with a co-device, and confirms.
 * The co-device must be a DIFFERENT active device on the same identity.
 *
 * @param device_fingerprint Fingerprint of the device to burn.
 * @param device_type 'tpm' or 'piv'.
 * @param co_device_fingerprint Fingerprint of the co-signing device.
 * @param co_device_type 'tpm' or 'piv'.
 * @param reason Optional reason for the burn.
 * @param credentials Optional pre-loaded credentials.
 */
export async function burnDevice(
  device_fingerprint: string,
  device_type: string,
  co_device_fingerprint: string,
  co_device_type: string,
  reason?: string | null,
  credentials?: StoredCredentials | null,
): Promise<BurnConfirmResult> {
  if (credentials == null) {
    credentials = load_credentials();
  }

  const burn_request = await requestBurn(device_fingerprint, device_type, reason, credentials);

  const co_device_signature_b64 = await _sign_burn_confirmation_with_co_device(
    burn_request.token_id, co_device_type, credentials,
  );

  return confirmBurn(
    burn_request.token_id,
    co_device_signature_b64,
    co_device_fingerprint,
    co_device_type,
    credentials,
  );
}


/**
 * Request a burn confirmation token (step 1 of 2).
 *
 * The returned token_id is valid for 5 minutes.
 */
export async function requestBurn(
  device_fingerprint: string,
  device_type: string,
  reason?: string | null,
  credentials?: StoredCredentials | null,
): Promise<BurnRequestResult> {
  if (credentials == null) {
    credentials = load_credentials();
  }

  const token = await get_token(false, credentials);
  const api_client = new OneIDAPIClient(credentials.api_base_url);

  const burn_token_data = await api_client.make_authenticated_request(
    "POST", "/api/v1/identity/devices/burn", token.access_token, {
      device_fingerprint,
      device_type,
      reason: reason ?? undefined,
    },
  );

  return {
    token_id: (burn_token_data.token_id ?? "") as string,
    expires_at: (burn_token_data.expires_at ?? "") as string,
    target_device_fingerprint: (burn_token_data.target_device_fingerprint ?? device_fingerprint) as string,
    target_device_type: (burn_token_data.target_device_type ?? device_type) as string,
    active_devices_remaining_after_burn: (burn_token_data.active_devices_remaining_after_burn ?? 0) as number,
  };
}


/**
 * Confirm a burn with a co-device signature (step 2 of 2).
 */
export async function confirmBurn(
  token_id: string,
  co_device_signature_b64: string,
  co_device_fingerprint: string,
  co_device_type: string,
  credentials?: StoredCredentials | null,
): Promise<BurnConfirmResult> {
  if (credentials == null) {
    credentials = load_credentials();
  }

  const token = await get_token(false, credentials);
  const api_client = new OneIDAPIClient(credentials.api_base_url);

  const confirm_data = await api_client.make_authenticated_request(
    "POST", "/api/v1/identity/devices/burn/confirm", token.access_token, {
      token_id,
      co_device_signature_b64,
      co_device_fingerprint,
      co_device_type,
    },
  );

  const server_reported_new_trust_tier = (confirm_data.new_trust_tier ?? null) as string | null;

  if (server_reported_new_trust_tier && server_reported_new_trust_tier !== credentials.trust_tier) {
    const updated_credentials: StoredCredentials = {
      ...credentials,
      trust_tier: server_reported_new_trust_tier,
    };
    save_credentials(updated_credentials);
  }

  invalidate_world_cache();

  return {
    burned_device_fingerprint: (confirm_data.burned_device_fingerprint ?? "") as string,
    burned_device_type: (confirm_data.burned_device_type ?? "") as string,
    burn_reason: (confirm_data.burn_reason ?? null) as string | null,
    confirmed_by_device_fingerprint: (confirm_data.confirmed_by_device_fingerprint ?? co_device_fingerprint) as string,
    confirmed_by_device_type: (confirm_data.confirmed_by_device_type ?? co_device_type) as string,
    remaining_active_devices: (confirm_data.remaining_active_devices ?? 0) as number,
    new_trust_tier: server_reported_new_trust_tier,
  };
}


async function _sign_burn_confirmation_with_co_device(
  token_id: string,
  co_device_type: string,
  credentials: StoredCredentials,
): Promise<string> {
  const message_to_sign = `BURN:${token_id}`;
  const message_bytes_b64 = Buffer.from(message_to_sign, "utf-8").toString("base64");

  if (co_device_type === "tpm") {
    const { sign_challenge_with_tpm } = await import("./helper.js");
    const ak_handle = credentials.hsm_key_reference ?? "";
    const sign_result = await sign_challenge_with_tpm(message_bytes_b64, ak_handle);
    return (sign_result.signature_b64 as string) ?? "";
  } else if (co_device_type === "piv") {
    const { sign_challenge_with_piv } = await import("./helper.js");
    const sign_result = await sign_challenge_with_piv(message_bytes_b64);
    return (sign_result.signature_b64 as string) ?? "";
  } else {
    throw new DeviceManagementError(
      `Unsupported co-device type '${co_device_type}' for burn confirmation. Must be 'tpm' or 'piv'.`,
      "UNSUPPORTED_DEVICE_TYPE",
    );
  }
}


/**
 * Register or update the human operator email for this identity.
 *
 * @param operator_email_address The email address to register.
 * @param credentials Optional pre-loaded credentials.
 * @returns True if the email was registered successfully.
 */
export async function registerOperatorEmail(
  operator_email_address: string,
  credentials?: StoredCredentials | null,
): Promise<boolean> {
  if (credentials == null) {
    credentials = load_credentials();
  }

  const token = await get_token(false, credentials);
  const api_client = new OneIDAPIClient(credentials.api_base_url);

  const response_data = await api_client.make_authenticated_request(
    "PUT",
    "/api/v1/identity/operator-email",
    token.access_token,
    { operator_email: operator_email_address },
  );

  invalidate_world_cache();

  return Boolean(response_data.operator_email_registered);
}
