/**
 * World/status endpoint for the 1id.com Node.js SDK.
 *
 * Fetches the full identity state from the server's world endpoint:
 * identity, devices, connected services, available services, and operator guidance.
 *
 * Results are cached for 5 minutes. Call invalidate_world_cache() to force a fresh fetch.
 */

import { load_credentials, type StoredCredentials } from "./credentials.js";
import { get_token } from "./auth.js";
import { OneIDAPIClient } from "./client.js";
import { NotEnrolledError } from "./exceptions.js";

const WORLD_CACHE_TTL_MILLISECONDS = 5 * 60 * 1000;

export interface WorldIdentitySection {
  internal_id: string;
  handle: string;
  trust_tier: string;
  display_name: string | null;
  agent_identity_urn: string | null;
  enrolled_at: string | null;
  hardware_locked: boolean;
  locked_at: string | null;
  hardware_lock_notice: string | null;
  operator_email_registered: boolean;
  credential_pointer_count: number;
}

export interface WorldDeviceEntry {
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

export interface WorldServiceEntry {
  service_id: string;
  service_name: string;
  service_type: string | null;
  category: string | null;
  status: string | null;
  primary_identifier: string | null;
  aliases: string[] | null;
  dashboard_url: string | null;
  description: string | null;
  minimum_trust_tier: string | null;
}

export interface WorldGuidanceItem {
  id: string;
  priority: string;
  title: string;
  description: string;
  human_action_url: string | null;
  agent_api_endpoint: string | null;
}

export interface WorldOperatorGuidance {
  message_for_human: string;
  items: WorldGuidanceItem[];
}

export interface WorldStatus {
  identity: WorldIdentitySection;
  devices: WorldDeviceEntry[];
  connected_services: WorldServiceEntry[];
  available_services: WorldServiceEntry[];
  operator_guidance: WorldOperatorGuidance | null;
  raw_data: Record<string, unknown>;
}

let cached_world_status: WorldStatus | null = null;
let cached_world_status_fetched_at: number = 0;

/**
 * Fetch the full world state from the server.
 *
 * Returns everything: identity, devices, connected services, available services,
 * and operator guidance. Results are cached for 5 minutes.
 *
 * @param credentials Optional pre-loaded credentials.
 * @returns WorldStatus with complete identity state.
 * @throws NotEnrolledError if no credentials exist.
 * @throws AuthenticationError if the token is invalid or expired.
 * @throws NetworkError if the server cannot be reached.
 */
export async function fetch_world_status_from_server(
  credentials?: StoredCredentials | null,
): Promise<WorldStatus> {
  if (cached_world_status != null) {
    const elapsed_since_cached_fetch = Date.now() - cached_world_status_fetched_at;
    if (elapsed_since_cached_fetch < WORLD_CACHE_TTL_MILLISECONDS) {
      return cached_world_status;
    }
  }

  if (credentials == null) {
    credentials = load_credentials();
  }

  const token = await get_token(false, credentials);
  const api_client = new OneIDAPIClient(credentials.api_base_url);

  const world_data = await api_client.make_authenticated_request(
    "GET",
    "/api/v1/identity/world",
    token.access_token,
  );

  const parsed_world_status = parse_world_response_to_world_status(world_data);

  cached_world_status = parsed_world_status;
  cached_world_status_fetched_at = Date.now();

  return parsed_world_status;
}

/**
 * Clear the cached world status, forcing a fresh fetch on next call.
 */
export function invalidate_world_cache(): void {
  cached_world_status = null;
  cached_world_status_fetched_at = 0;
}

function parse_world_response_to_world_status(data: Record<string, unknown>): WorldStatus {
  const raw_identity = (data.identity ?? {}) as Record<string, unknown>;
  const raw_devices = (data.devices ?? []) as Record<string, unknown>[];
  const raw_connected = (data.connected_services ?? []) as Record<string, unknown>[];
  const raw_available = (data.available_services ?? []) as Record<string, unknown>[];
  const raw_guidance = data.operator_guidance as Record<string, unknown> | null;

  const identity: WorldIdentitySection = {
    internal_id: (raw_identity.internal_id ?? raw_identity.agent_id ?? "") as string,
    handle: (raw_identity.handle ?? "") as string,
    trust_tier: (raw_identity.trust_tier ?? "declared") as string,
    display_name: (raw_identity.display_name ?? null) as string | null,
    agent_identity_urn: (raw_identity.agent_identity_urn ?? null) as string | null,
    enrolled_at: (raw_identity.enrolled_at ?? null) as string | null,
    hardware_locked: Boolean(raw_identity.hardware_locked),
    locked_at: (raw_identity.locked_at ?? null) as string | null,
    hardware_lock_notice: (raw_identity.hardware_lock_notice ?? null) as string | null,
    operator_email_registered: Boolean(raw_identity.operator_email_registered),
    credential_pointer_count: (raw_identity.credential_pointer_count ?? 0) as number,
  };

  const devices: WorldDeviceEntry[] = raw_devices.map((device_data) => ({
    device_type: (device_data.device_type ?? "") as string,
    device_fingerprint: (device_data.device_fingerprint ?? "") as string,
    device_status: (device_data.device_status ?? "active") as string,
    trust_tier: (device_data.trust_tier ?? null) as string | null,
    tpm_manufacturer: (device_data.tpm_manufacturer ?? null) as string | null,
    piv_serial: (device_data.piv_serial ?? null) as string | null,
    bound_at: (device_data.bound_at ?? null) as string | null,
    burned_at: (device_data.burned_at ?? null) as string | null,
    burn_reason: (device_data.burn_reason ?? null) as string | null,
  }));

  const connected_services: WorldServiceEntry[] = raw_connected.map(parse_service_entry_from_raw_data);
  const available_services: WorldServiceEntry[] = raw_available.map(parse_service_entry_from_raw_data);

  let operator_guidance: WorldOperatorGuidance | null = null;
  if (raw_guidance != null) {
    const raw_items = (raw_guidance.items ?? []) as Record<string, unknown>[];
    operator_guidance = {
      message_for_human: (raw_guidance.message_for_human ?? "") as string,
      items: raw_items.map((item_data) => ({
        id: (item_data.id ?? "") as string,
        priority: (item_data.priority ?? "recommended") as string,
        title: (item_data.title ?? "") as string,
        description: (item_data.description ?? "") as string,
        human_action_url: (item_data.human_action_url ?? null) as string | null,
        agent_api_endpoint: (item_data.agent_api_endpoint ?? null) as string | null,
      })),
    };
  }

  return {
    identity,
    devices,
    connected_services,
    available_services,
    operator_guidance,
    raw_data: data,
  };
}

function parse_service_entry_from_raw_data(raw: Record<string, unknown>): WorldServiceEntry {
  return {
    service_id: (raw.service_id ?? "") as string,
    service_name: (raw.service_name ?? "") as string,
    service_type: (raw.service_type ?? null) as string | null,
    category: (raw.category ?? null) as string | null,
    status: (raw.status ?? raw.account_status ?? null) as string | null,
    primary_identifier: (raw.primary_identifier ?? null) as string | null,
    aliases: (raw.aliases ?? null) as string[] | null,
    dashboard_url: (raw.dashboard_url ?? null) as string | null,
    description: (raw.description ?? null) as string | null,
    minimum_trust_tier: (raw.minimum_trust_tier ?? null) as string | null,
  };
}
