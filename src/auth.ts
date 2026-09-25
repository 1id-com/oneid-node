/**
 * OAuth2 token management for the 1id.com Node.js SDK.
 *
 * After enrollment, agents authenticate via hardware challenge-response
 * (TPM for sovereign/virtual, PIV for portable, Secure Enclave for enclave) or,
 * for the declared tier, the same challenge signed by the enrolled software key.
 * Every token is sender-constrained (cnf.jwk): the SDK signs each request with
 * the enrolled key (RFC 9421, registry-04 "HTTP Message Signatures").
 *
 * SECURITY RULE: Hardware-tier identities NEVER fall back to bare
 * client_credentials. If the hardware device is absent, get_token() throws
 * HardwareDeviceNotPresentError. This is intentional: a stolen
 * credentials.json is useless without the physical device.
 *
 * Token endpoint (F-05 hardened):
 *   POST https://1id.com/api/v1/auth/challenge + /verify  (hardware tiers)
 *   Direct Keycloak token endpoint is blocked by nginx to external clients.
 */

import { type StoredCredentials, load_credentials, local_signing_device_type_for_credentials } from "./credentials.js";
import { AuthenticationError, HardwareDeviceNotPresentError, NetworkError } from "./exceptions.js";
import type { Token } from "./identity.js";
import { OneIDAPIClient } from "./client.js";
import * as crypto from "node:crypto";
import {
  type AirsRequestSigner,
  convert_der_ecdsa_signature_to_rfc9421_raw_r_and_s,
  server_clock_offset_seconds_from_access_token,
} from "./airsHttpMessageSignatures.js";

const TOKEN_REFRESH_MARGIN_MILLISECONDS = 60_000;
const TOKEN_REQUEST_TIMEOUT_MILLISECONDS = 15_000;

/**
 * Token cache, one entry per identity (AUD-F55): a process can hold several AIRS
 * identities; a cached token is returned only for the identity (token endpoint,
 * client, enrolled key) it was issued to. Same keying as the Python SDK.
 */
const cached_tokens_by_identity = new Map<string, Token>();

function token_cache_key_for_credentials(credentials: StoredCredentials): string {
  return JSON.stringify([
    credentials.token_endpoint || credentials.api_base_url || "",
    credentials.client_id || "",
    credentials.hsm_key_reference || "",
    crypto.createHash("sha256").update(credentials.private_key_pem || "", "utf-8").digest("hex"),
  ]);
}

function remember_token_for_credentials(credentials: StoredCredentials, token: Token): void {
  cached_tokens_by_identity.set(token_cache_key_for_credentials(credentials), token);
}

/**
 * Get a valid OAuth2 access token, refreshing if needed.
 *
 * For hardware-backed tiers (sovereign, portable, virtual), this invokes
 * the hardware challenge-response flow via the Go binary. The physical
 * device must be present. If it is absent, HardwareDeviceNotPresentError
 * is thrown -- there is NO fallback to bare client_credentials.
 *
 * For declared tier, the challenge is signed with the enrolled software key
 * (Binding-Proof Authentication); the client_secret is never sent.
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
  if (credentials == null) {
    credentials = load_credentials();
  }

  const cached_token = cached_tokens_by_identity.get(token_cache_key_for_credentials(credentials));
  if (!force_refresh && cached_token != null) {
    const margin_adjusted_expiry = new Date(cached_token.expires_at.getTime() - TOKEN_REFRESH_MARGIN_MILLISECONDS);
    if (new Date() < margin_adjusted_expiry) {
      return cached_token;
    }
  }

  const device_type = local_signing_device_type_for_credentials(credentials);
  const token = (device_type === "piv" || device_type === "enclave" || device_type === "tpm")
    ? await authenticate_with_hardware_challenge_response(credentials)
    : await authenticate_with_declared_software_key(credentials);
  remember_token_for_credentials(credentials, token);
  return token;
}

/**
 * Route to PIV, TPM or Secure Enclave challenge-response by the ENROLLED LOCAL
 * DEVICE (local_signing_device_type_for_credentials: hsm_key_reference first,
 * the trust tier only as the fallback), because an identity's tier and its local
 * device differ after recovery or device addition (AUD-F66, AUD-LOST1). Same
 * rule as the Python SDK. Never falls back to client_credentials.
 */
async function authenticate_with_hardware_challenge_response(credentials: StoredCredentials): Promise<Token> {
  const device_type = local_signing_device_type_for_credentials(credentials);
  const authenticators: Record<string, [string, string, () => Promise<Token>]> = {
    piv: ["PIV", "YubiKey", () => authenticate_with_piv(null, null, credentials)],
    tpm: ["TPM", "Device", () => authenticate_with_tpm(null, null, null, credentials)],
    enclave: ["Secure Enclave", "Enclave", () => authenticate_with_enclave(null, null, credentials)],
  };
  const selected = device_type != null ? authenticators[device_type] : undefined;
  if (selected === undefined) {
    throw new HardwareDeviceNotPresentError(
      `Trust tier '${credentials.trust_tier}' requires hardware but no ` +
      `supported authentication method is available.`
    );
  }
  const [mechanism_name, device_name, authenticate] = selected;
  try {
    return await authenticate();
  } catch (error) {
    if (error instanceof HardwareDeviceNotPresentError) { throw error; }
    throw new HardwareDeviceNotPresentError(
      `${mechanism_name} authentication failed and hardware is required for ` +
      `${credentials.trust_tier} tier. ${device_name} may be absent or ` +
      `inaccessible: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Build the function that signs an RFC 9421 signature base with the enrolled
 * key that authenticates this identity (registry-04 sender constraint,
 * OWN-038): "tpm" (the AK via oneid-enroll >= 2.2.0, which hashes inputs over
 * 1024 bytes with a TPM hash sequence), "piv" (slot 9a), "enclave" (Secure
 * Enclave) or "declared" (the enrolled software key). Every call reaches the
 * hardware; nothing is cached. ECDSA signatures are returned as r||s.
 */
export function build_airs_request_signer_for_enrolled_key(
  enrolled_key_kind: "tpm" | "piv" | "enclave" | "declared",
  options: { ak_handle?: string | null; software_private_key_pem?: string | null } = {},
): AirsRequestSigner {
  if (enrolled_key_kind === "tpm") {
    return async (signature_base: Buffer) => {
      const { sign_challenge_with_tpm } = await import("./helper.js");
      const result = await sign_challenge_with_tpm(signature_base.toString("base64"), options.ak_handle ?? "");
      return Buffer.from(result.signature_b64 as string, "base64");
    };
  }
  if (enrolled_key_kind === "piv") {
    return async (signature_base: Buffer) => {
      const { sign_challenge_with_piv } = await import("./helper.js");
      const result = await sign_challenge_with_piv(signature_base.toString("base64"));
      return ecdsa_signature_as_raw_r_and_s(Buffer.from(result.signature_b64 as string, "base64"));
    };
  }
  if (enrolled_key_kind === "enclave") {
    return async (signature_base: Buffer) => {
      const { sign_challenge_with_enclave } = await import("./helper.js");
      const result = await sign_challenge_with_enclave(signature_base.toString("base64"));
      return ecdsa_signature_as_raw_r_and_s(Buffer.from(result.signature_b64 as string, "base64"));
    };
  }
  if (!options.software_private_key_pem) {
    throw new AuthenticationError("declared identity has no enrolled software key to sign requests with");
  }
  const private_key = crypto.createPrivateKey(options.software_private_key_pem);
  return async (signature_base: Buffer) => {
    if (private_key.asymmetricKeyType === "ec") {
      return crypto.sign("sha256", signature_base, { key: private_key, dsaEncoding: "ieee-p1363" });
    }
    if (private_key.asymmetricKeyType === "rsa") {
      return crypto.sign("sha256", signature_base, private_key);
    }
    if (private_key.asymmetricKeyType === "ed25519") {
      return crypto.sign(null, signature_base, private_key);
    }
    throw new AuthenticationError(`Unsupported enrolled key type: ${private_key.asymmetricKeyType}`);
  };
}

function ecdsa_signature_as_raw_r_and_s(signature: Buffer): Buffer {
  // strict DER first (PIV + Secure Enclave return DER); a 64-octet value that
  // is not exact DER is already r||s
  try {
    return convert_der_ecdsa_signature_to_rfc9421_raw_r_and_s(signature);
  } catch (der_error) {
    if (signature.length === 64) { return signature; }
    throw new AuthenticationError(`ECDSA P-256 signature is neither DER nor 64-octet r||s: ${der_error}`);
  }
}

/** The token's cnf.jwk, read without verification (used only as the RFC 9421 keyid). */
export function confirmation_jwk_from_access_token(access_token: string): Record<string, string> | null {
  try {
    const payload = JSON.parse(Buffer.from(access_token.split(".")[1], "base64url").toString("utf8"));
    const jwk = payload?.cnf?.jwk;
    return jwk && typeof jwk === "object" ? jwk as Record<string, string> : null;
  } catch {
    return null;
  }
}

/**
 * Declared-tier Binding-Proof Authentication: sign the server's nonce with the
 * software key enrolled for this identity (the Registrar checks it against the
 * key's RFC 7638 thumbprint recorded at enrollment). No static client_secret is
 * sent (registry draft, "Client Credentials Grant"; external review 072 #6).
 */
export async function authenticate_with_declared_software_key(
  credentials?: StoredCredentials | null,
): Promise<Token> {
  if (credentials == null) {
    credentials = load_credentials();
  }
  if (!credentials.private_key_pem) {
    throw new AuthenticationError(
      "This declared identity has no enrolled signing key in its credentials file, " +
      "so it cannot perform binding-proof authentication."
    );
  }
  const api_client = new OneIDAPIClient(credentials.api_base_url, TOKEN_REQUEST_TIMEOUT_MILLISECONDS);

  let challenge_data: Record<string, unknown>;
  try {
    challenge_data = await api_client["_make_request"]("POST", "/api/v1/auth/challenge", {
      identity_id: credentials.client_id,
      device_type: "declared",
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

  const private_key = crypto.createPrivateKey(credentials.private_key_pem);
  const nonce = Buffer.from(nonce_b64, "base64");
  let signature: Buffer;
  if (private_key.asymmetricKeyType === "ec") {
    signature = crypto.sign("sha256", nonce, { key: private_key, dsaEncoding: "der" });
  } else if (private_key.asymmetricKeyType === "rsa") {
    signature = crypto.sign("sha256", nonce, private_key);
  } else if (private_key.asymmetricKeyType === "ed25519") {
    signature = crypto.sign(null, nonce, private_key);
  } else {
    throw new AuthenticationError(`Unsupported enrolled key type: ${private_key.asymmetricKeyType}`);
  }
  const public_key_pem = crypto.createPublicKey(private_key).export({ type: "spki", format: "pem" }).toString();

  let verify_data: Record<string, unknown>;
  try {
    verify_data = await api_client["_make_request"]("POST", "/api/v1/auth/verify", {
      challenge_id,
      signature_b64: signature.toString("base64"),
      public_key_pem,
    });
  } catch (error) {
    if (error instanceof NetworkError) { throw error; }
    throw new AuthenticationError(
      `Declared-tier binding-proof authentication failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
  const tokens = verify_data.authenticated ? verify_data.tokens as Record<string, unknown> | undefined : undefined;
  if (!tokens?.access_token) {
    throw new AuthenticationError("Binding proof verified but no tokens were issued");
  }
  const expires_in_seconds = (tokens.expires_in as number) ?? 3600;
  return {
    access_token: tokens.access_token as string,
    token_type: (tokens.token_type as string) ?? "Bearer",
    expires_at: new Date(Date.now() + expires_in_seconds * 1000),
    refresh_token: (tokens.refresh_token as string) ?? null,
    airs_request_signer: build_airs_request_signer_for_enrolled_key(
      "declared", { software_private_key_pem: credentials.private_key_pem }),
    confirmation_jwk: confirmation_jwk_from_access_token(tokens.access_token as string),
    server_clock_offset_seconds: server_clock_offset_seconds_from_access_token(tokens.access_token as string),
  };
}

/**
 * Clear the in-memory cached token.
 *
 * Useful for testing or when credentials have changed.
 */
export function clear_cached_token(): void {
  cached_tokens_by_identity.clear();
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

  // OWN-039: fetch/verify the helper BEFORE asking for a challenge -- a first
  // download on a slow link (minutes) must not outlive the challenge.
  const { ensure_binary_available } = await import("./helper.js");
  await ensure_binary_available();

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
      airs_request_signer: build_airs_request_signer_for_enrolled_key("tpm", { ak_handle }),
      confirmation_jwk: confirmation_jwk_from_access_token(tokens.access_token as string),
      server_clock_offset_seconds: server_clock_offset_seconds_from_access_token(tokens.access_token as string),
    };
    remember_token_for_credentials(credentials, token);
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

  // OWN-039: fetch/verify the helper BEFORE asking for a challenge -- a first
  // download on a slow link (minutes) must not outlive the challenge.
  const { ensure_binary_available } = await import("./helper.js");
  await ensure_binary_available();

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
      airs_request_signer: build_airs_request_signer_for_enrolled_key("piv"),
      confirmation_jwk: confirmation_jwk_from_access_token(tokens.access_token as string),
      server_clock_offset_seconds: server_clock_offset_seconds_from_access_token(tokens.access_token as string),
    };
    remember_token_for_credentials(credentials, token);
    return token;
  } else {
    throw new AuthenticationError(
      "PIV signature verified but no tokens were issued. " +
      "The Keycloak token endpoint may be unavailable."
    );
  }
}


// ---------------------------------------------------------------------------
// Secure Enclave authentication (enclave tier -- Apple Silicon Macs)
// ---------------------------------------------------------------------------

/**
 * Authenticate using the Apple Secure Enclave -- passwordless sign-in.
 *
 * Same challenge-response flow as TPM/PIV but uses the P-256 key stored
 * in the Secure Enclave via the oneid-se-helper binary.
 *
 * @param identity_id The 1id internal ID. If null, loaded from credentials.
 * @param api_base_url Base URL for the 1id API.
 * @param credentials Pre-loaded credentials. If null, loaded from file.
 * @returns A valid Token object.
 */
export async function authenticate_with_enclave(
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
      device_type: "enclave",
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

  const { sign_challenge_with_enclave } = await import("./helper.js");
  const sign_result = await sign_challenge_with_enclave(nonce_b64);
  const signature_b64 = (sign_result.signature_b64 as string) ?? "";

  if (!signature_b64) {
    throw new AuthenticationError("Secure Enclave signing returned empty signature");
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
      `Secure Enclave authentication failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  if (!verify_data.authenticated) {
    throw new AuthenticationError("Server did not confirm Secure Enclave authentication");
  }

  const tokens = verify_data.tokens as Record<string, unknown> | undefined;
  if (tokens?.access_token) {
    const expires_in_seconds = (tokens.expires_in as number) ?? 3600;
    const token: Token = {
      access_token: tokens.access_token as string,
      token_type: (tokens.token_type as string) ?? "Bearer",
      expires_at: new Date(Date.now() + expires_in_seconds * 1000),
      refresh_token: (tokens.refresh_token as string) ?? null,
      airs_request_signer: build_airs_request_signer_for_enrolled_key("enclave"),
      confirmation_jwk: confirmation_jwk_from_access_token(tokens.access_token as string),
      server_clock_offset_seconds: server_clock_offset_seconds_from_access_token(tokens.access_token as string),
    };
    remember_token_for_credentials(credentials, token);
    return token;
  } else {
    throw new AuthenticationError(
      "Secure Enclave signature verified but no tokens were issued. " +
      "The Keycloak token endpoint may be unavailable."
    );
  }
}
