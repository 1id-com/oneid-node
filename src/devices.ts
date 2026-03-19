/**
 * Device management and hardware lock for the 1id.com Node.js SDK.
 *
 * Provides:
 *   listDevices()   -- List all devices (active and burned) bound to this identity
 *   lockHardware()  -- Permanently lock identity to its single hardware device (irreversible)
 *
 * Usage:
 *   import { listDevices, lockHardware } from "1id/devices";
 *
 *   const result = await listDevices();
 *   for (const d of result.devices) { console.log(`${d.device_type} [${d.device_status}]`); }
 *
 *   const lock = await lockHardware();
 *   console.log(`Locked: ${lock.hardware_locked}`);
 */

import { load_credentials, type StoredCredentials } from "./credentials.js";
import { get_token } from "./auth.js";
import { OneIDAPIClient } from "./client.js";
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
