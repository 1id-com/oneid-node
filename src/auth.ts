/**
 * OAuth2 token management for the 1id.com Node.js SDK.
 *
 * After enrollment, agents authenticate via hardware challenge-response
 * (TPM for sovereign/virtual, PIV for portable) or OAuth2 client_credentials
 * grant (declared tier only).
 *
 * SECURITY RULE: Hardware-tier identities NEVER fall back to bare
 * client_credentials. If the hardware device is absent, get_token() throws
 * HardwareDeviceNotPresentError. This is intentional: a stolen
 * credentials.json is useless without the physical device.
 *
 * Token endpoint (F-05 hardened):
 *   POST https://1id.com/api/v1/auth/token  (declared tier only)
 *   POST https://1id.com/api/v1/auth/challenge + /verify  (hardware tiers)
 *   Direct Keycloak token endpoint is blocked by nginx to external clients.
 */

import { type StoredCredentials, load_credentials } from "./credentials.js";
import { AuthenticationError, HardwareDeviceNotPresentError, NetworkError } from "./exceptions.js";
import type { Token } from "./identity.js";
import { OneIDAPIClient } from "./client.js";

const TOKEN_REFRESH_MARGIN_MILLISECONDS = 60_000;
const TOKEN_REQUEST_TIMEOUT_MILLISECONDS = 15_000;

const TIERS_REQUIRING_HARDWARE_AUTH = new Set(["sovereign", "portable", "enclave", "virtual"]);
const TIERS_USING_TPM = new Set(["sovereign", "virtual"]);
const TIERS_USING_PIV = new Set(["portable"]);
const TIERS_USING_ENCLAVE = new Set(["enclave"]);

let cached_token: Token | null = null;

/**
 * Get a valid OAuth2 access token, refreshing if needed.
 *
 * For hardware-backed tiers (sovereign, portable, virtual), this invokes
 * the hardware challenge-response flow via the Go binary. The physical
 * device must be present. If it is absent, HardwareDeviceNotPresentError
 * is thrown -- there is NO fallback to bare client_credentials.
 *
 * For declared tier, the standard OAuth2 client_credentials grant is used.
 *
 * @param force_refresh If true, always fetch a new token even if cached.
 * @param credentials Optional pre-loaded credentials.
 * @returns A valid Token object.
 * @throws NotEnrolledError if no credentials file exists.
 * @throws HardwareDeviceNotPresentError if hardware tier and device is absent.
 * @throws AuthenticationError if the token request fails.
 * @throws NetworkError if the token endpoint cannot be reached.
 */
export async function get_token(
  force_refresh: boolean = false,
  credentials?: StoredCredentials | null,
): Promise<Token> {
  if (!force_refresh && cached_token != null) {
    const margin_adjusted_expiry = new Date(cached_token.expires_at.getTime() - TOKEN_REFRESH_MARGIN_MILLISECONDS);
    if (new Date() < margin_adjusted_expiry) {
      return cached_token;
    }
  }

  if (credentials == null) {
    credentials = load_credentials();
  }

  if (TIERS_REQUIRING_HARDWARE_AUTH.has(credentials.trust_tier)) {
    const token = await authenticate_with_hardware_challenge_response(credentials);
    cached_token = token;
    return token;
  }

  const token = await request_token_from_keycloak(credentials);
  cached_token = token;
  return token;
}

async function authenticate_with_hardware_challenge_response(credentials: StoredCredentials): Promise<Token> {
  if (TIERS_USING_TPM.has(credentials.trust_tier)) {
    try {
      return await authenticate_with_tpm(null, null, null, credentials);
    } catch (error) {
      if (error instanceof HardwareDeviceNotPresentError) { throw error; }
      throw new HardwareDeviceNotPresentError(
        `TPM authentication failed and hardware is required for ` +
        `${credentials.trust_tier} tier. Device may be absent or ` +
        `inaccessible: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  if (TIERS_USING_PIV.has(credentials.trust_tier)) {
    try {
      return await authenticate_with_piv(null, null, credentials);
    } catch (error) {
      if (error instanceof HardwareDeviceNotPresentError) { throw error; }
      throw new HardwareDeviceNotPresentError(
        `PIV authentication failed and hardware is required for ` +
        `${credentials.trust_tier} tier. YubiKey may be absent or ` +
        `inaccessible: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  throw new HardwareDeviceNotPresentError(
    `Trust tier '${credentials.trust_tier}' requires hardware but no ` +
    `supported authentication method is available.`
  );
}

/**
 * Request a new access token from Keycloak using client_credentials grant.
 */
async function request_token_from_keycloak(credentials: StoredCredentials): Promise<Token> {
  const api_client = new OneIDAPIClient(
    credentials.api_base_url,
    TOKEN_REQUEST_TIMEOUT_MILLISECONDS,
  );

  let token_response: Record<string, unknown>;
  try {
    token_response = await api_client.get_token_with_client_credentials(
      credentials.client_id,
      credentials.client_secret,
    );
  } catch (error) {
    if (error instanceof NetworkError || error instanceof AuthenticationError) {
      throw error;
    }
    throw new AuthenticationError(
      `Token request failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const access_token = token_response.access_token as string;
  if (!access_token) {
    throw new AuthenticationError("Token response missing 'access_token' field");
  }

  const expires_in_seconds = (token_response.expires_in as number) ?? 3600;
  const expires_at = new Date(Date.now() + expires_in_seconds * 1000);

  return {
    access_token,
    token_type: (token_response.token_type as string) ?? "Bearer",
    expires_at,
    refresh_token: (token_response.refresh_token as string) ?? null,
  };
}

/**
 * Clear the in-memory cached token.
 *
 * Useful for testing or when credentials have changed.
 */
export function clear_cached_token(): void {
  cached_token = null;
}

// ---------------------------------------------------------------------------
// TPM-backed passwordless authentication (sovereign/virtual tier)
// ---------------------------------------------------------------------------

/**
 * Authenticate using the TPM -- passwordless, zero-elevation sign-in.
 *
 * This is the "OAuth for agents" flow:
 *   1. Requests a challenge nonce from the server
 *   2. Signs it with the TPM AK (no elevation needed)
 *   3. Sends the signature back to the server
 *   4. Server verifies and issues a JWT
 *
 * @param identity_id The 1id internal ID. If null, loaded from credentials.
 * @param ak_handle The AK persistent handle (hex). If null, loaded from credentials.
 * @param api_base_url Base URL for the 1id API.
 * @param credentials Pre-loaded credentials. If null, loaded from file.
 * @returns A valid Token object.
 */
export async function authenticate_with_tpm(
  identity_id?: string | null,
  ak_handle?: string | null,
  api_base_url?: string | null,
  credentials?: StoredCredentials | null,
): Promise<Token> {
  // Load credentials if not provided
  if (credentials == null) {
    credentials = load_credentials();
  }

  if (identity_id == null) {
    identity_id = credentials.client_id;
  }

  if (ak_handle == null) {
    ak_handle = credentials.hsm_key_reference ?? null;
    if (!ak_handle) {
      throw new AuthenticationError(
        "No AK handle found in credentials. TPM authentication requires " +
        "a sovereign or virtual tier enrollment with a TPM."
      );
    }
  }

  if (api_base_url == null) {
    api_base_url = credentials.api_base_url;
  }

  const api_client = new OneIDAPIClient(api_base_url, TOKEN_REQUEST_TIMEOUT_MILLISECONDS);

  let challenge_data: Record<string, unknown>;
  try {
    challenge_data = await api_client["_make_request"]("POST", "/api/v1/auth/challenge", {
      identity_id,
      device_type: "tpm",
    });
  } catch (error) {
    if (error instanceof NetworkError) { throw error; }
    throw new AuthenticationError(
      `Challenge request failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const challenge_id = challenge_data.challenge_id as string;
  const nonce_b64 = challenge_data.nonce_b64 as string;

  if (!challenge_id || !nonce_b64) {
    throw new AuthenticationError("Server returned incomplete challenge response");
  }

  // Step 2: Sign the nonce with the TPM AK (NO elevation needed)
  const { sign_challenge_with_tpm } = await import("./helper.js");
  const sign_result = await sign_challenge_with_tpm(nonce_b64, ak_handle);
  const signature_b64 = sign_result.signature_b64 ?? "";

  if (!signature_b64) {
    throw new AuthenticationError("TPM signing returned empty signature");
  }

  // Step 3: Send the signature to the server for verification
  let verify_data: Record<string, unknown>;
  try {
    verify_data = await api_client["_make_request"]("POST", "/api/v1/auth/verify", {
      challenge_id,
      signature_b64,
    });
  } catch (error) {
    if (error instanceof NetworkError) { throw error; }
    throw new AuthenticationError(
      `TPM authentication failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  if (!verify_data.authenticated) {
    throw new AuthenticationError("Server did not confirm authentication");
  }

  // Extract token from response
  const tokens = verify_data.tokens as Record<string, unknown> | undefined;
  if (tokens?.access_token) {
    const expires_in_seconds = (tokens.expires_in as number) ?? 3600;
    const token: Token = {
      access_token: tokens.access_token as string,
      token_type: (tokens.token_type as string) ?? "Bearer",
      expires_at: new Date(Date.now() + expires_in_seconds * 1000),
      refresh_token: (tokens.refresh_token as string) ?? null,
    };
    cached_token = token;
    return token;
  } else {
    throw new AuthenticationError(
      "TPM signature verified but no tokens were issued. " +
      "The Keycloak token endpoint may be unavailable."
    );
  }
}


/**
 * Authenticate using a PIV device (YubiKey) -- passwordless sign-in.
 *
 * Same challenge-response flow as TPM but uses PIV slot 9a ECDSA signing.
 * No PIN, no elevation, no human interaction required.
 */
export async function authenticate_with_piv(
  identity_id?: string | null,
  api_base_url?: string | null,
  credentials?: StoredCredentials | null,
): Promise<Token> {
  if (credentials == null) {
    credentials = load_credentials();
  }

  if (identity_id == null) {
    identity_id = credentials.client_id;
  }

  if (api_base_url == null) {
    api_base_url = credentials.api_base_url;
  }

  const api_client = new OneIDAPIClient(api_base_url, TOKEN_REQUEST_TIMEOUT_MILLISECONDS);

  let challenge_data: Record<string, unknown>;
  try {
    challenge_data = await api_client["_make_request"]("POST", "/api/v1/auth/challenge", {
      identity_id,
      device_type: "piv",
    });
  } catch (error) {
    if (error instanceof NetworkError) { throw error; }
    throw new AuthenticationError(
      `Challenge request failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const challenge_id = challenge_data.challenge_id as string;
  const nonce_b64 = challenge_data.nonce_b64 as string;

  if (!challenge_id || !nonce_b64) {
    throw new AuthenticationError("Server returned incomplete challenge response");
  }

  const { sign_challenge_with_piv } = await import("./helper.js");
  const sign_result = await sign_challenge_with_piv(nonce_b64);
  const signature_b64 = sign_result.signature_b64 ?? "";

  if (!signature_b64) {
    throw new AuthenticationError("PIV signing returned empty signature");
  }

  let verify_data: Record<string, unknown>;
  try {
    verify_data = await api_client["_make_request"]("POST", "/api/v1/auth/verify", {
      challenge_id,
      signature_b64,
    });
  } catch (error) {
    if (error instanceof NetworkError) { throw error; }
    throw new AuthenticationError(
      `PIV authentication failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  if (!verify_data.authenticated) {
    throw new AuthenticationError("Server did not confirm PIV authentication");
  }

  const tokens = verify_data.tokens as Record<string, unknown> | undefined;
  if (tokens?.access_token) {
    const expires_in_seconds = (tokens.expires_in as number) ?? 3600;
    const token: Token = {
      access_token: tokens.access_token as string,
      token_type: (tokens.token_type as string) ?? "Bearer",
      expires_at: new Date(Date.now() + expires_in_seconds * 1000),
      refresh_token: (tokens.refresh_token as string) ?? null,
    };
    cached_token = token;
    return token;
  } else {
    throw new AuthenticationError(
      "PIV signature verified but no tokens were issued. " +
      "The Keycloak token endpoint may be unavailable."
    );
  }
}
