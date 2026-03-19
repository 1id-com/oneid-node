/**
 * Credential Pointer management for the 1id.com Node.js SDK.
 *
 * Manages the lightweight pointer registry that links an agent's identity
 * to credentials held by external credential authorities. 1ID never stores
 * credential content -- only pointer metadata (issuer, type, verification URL).
 *
 * Consent tokens enforce agent-initiated registration:
 *   1. Agent calls generateConsentToken(issuer_id, credential_type) -> token
 *   2. Agent gives the token to the credential authority
 *   3. Authority calls the server's register endpoint with the token
 *   4. Server validates: token is valid, not expired, not used, scopes match
 *
 * Usage:
 *   import oneid from "1id";
 *   import { generateConsentToken, listCredentialPointers } from "1id";
 *
 *   const token = await generateConsentToken("did:web:university.example", "degree");
 *   console.log(`Send this to the CA: ${token.consent_token_id}`);
 *
 *   const result = await listCredentialPointers();
 *   for (const p of result.pointers) {
 *     console.log(`${p.issuer_name}: ${p.credential_type} [${p.verification_url}]`);
 *   }
 */

import { OneIDAPIClient } from "./client.js";
import { StoredCredentials, load_credentials, DEFAULT_API_BASE_URL } from "./credentials.js";
import { get_token } from "./auth.js";
import { NetworkError } from "./exceptions.js";

export interface ConsentTokenResult {
  consent_token_id: string;
  issuer_id: string;
  credential_type: string;
  expires_at: string;
}

export interface CredentialPointerInfo {
  pointer_id: string;
  issuer_id: string;
  issuer_name: string;
  credential_type: string;
  credential_scope: string | null;
  verification_url: string;
  publicly_visible: boolean;
  valid_from: string | null;
  valid_until: string | null;
  registered_at: string | null;
  removed_at: string | null;
}

export interface CredentialPointerListResult {
  agent_id: string;
  pointers: CredentialPointerInfo[];
  pointer_count: number;
  view: string;
}

function parse_pointer_from_api_response(raw: Record<string, unknown>): CredentialPointerInfo {
  return {
    pointer_id: (raw.pointer_id ?? "") as string,
    issuer_id: (raw.issuer_id ?? "") as string,
    issuer_name: (raw.issuer_name ?? "") as string,
    credential_type: (raw.credential_type ?? "") as string,
    credential_scope: (raw.credential_scope ?? null) as string | null,
    verification_url: (raw.verification_url ?? "") as string,
    publicly_visible: Boolean(raw.publicly_visible),
    valid_from: (raw.valid_from ?? null) as string | null,
    valid_until: (raw.valid_until ?? null) as string | null,
    registered_at: (raw.registered_at ?? null) as string | null,
    removed_at: (raw.removed_at ?? null) as string | null,
  };
}

async function make_authenticated_credential_pointer_request(
  method: string,
  api_path: string,
  json_body?: Record<string, unknown> | null,
  credentials?: StoredCredentials | null,
): Promise<Record<string, unknown>> {
  if (credentials == null) {
    credentials = load_credentials();
  }
  const token = await get_token(false, credentials);
  const api_client = new OneIDAPIClient(credentials.api_base_url);
  return api_client.make_authenticated_request(method, api_path, token.access_token, json_body);
}

/**
 * Generate a scoped, single-use consent token for a credential authority.
 *
 * Give the returned token_id to the credential authority. The authority
 * uses it in a POST /api/v1/identity/credential-pointers call to register
 * a pointer.
 *
 * @param issuer_id DID or URI of the credential authority (e.g. "did:web:university.example").
 * @param credential_type The type of credential being authorized (e.g. "degree", "license").
 * @param valid_for_seconds How long the token is valid (60..604800, default 86400).
 * @param credentials Optional pre-loaded credentials.
 * @returns ConsentTokenResult with the token_id, scoped issuer/type, and expiry.
 */
export async function generateConsentToken(
  issuer_id: string,
  credential_type: string,
  valid_for_seconds: number = 86400,
  credentials?: StoredCredentials | null,
): Promise<ConsentTokenResult> {
  const raw_data = await make_authenticated_credential_pointer_request(
    "POST",
    "/api/v1/identity/credential-pointer-consent",
    { issuer_id, credential_type, valid_for_seconds },
    credentials,
  );

  return {
    consent_token_id: (raw_data.token_id ?? "") as string,
    issuer_id: (raw_data.issuer_id ?? issuer_id) as string,
    credential_type: (raw_data.credential_type ?? credential_type) as string,
    expires_at: (raw_data.expires_at ?? "") as string,
  };
}

/**
 * List credential pointers for an identity.
 *
 * If agent_id is null or matches the current identity, makes an
 * authenticated request returning all active pointers (full view).
 * If agent_id is a different identity, makes an unauthenticated
 * request returning only publicly visible pointers.
 *
 * @param agent_id Identity to query. Null = query your own pointers.
 * @param credentials Optional pre-loaded credentials.
 * @returns CredentialPointerListResult with the list of pointers and metadata.
 */
export async function listCredentialPointers(
  agent_id?: string | null,
  credentials?: StoredCredentials | null,
): Promise<CredentialPointerListResult> {
  if (credentials == null) {
    credentials = load_credentials();
  }

  if (agent_id == null) {
    agent_id = credentials.client_id;
  }

  const this_request_is_for_own_identity = (credentials.client_id === agent_id);
  const api_path = `/api/v1/identity/${agent_id}/credential-pointers`;

  let raw_data: Record<string, unknown>;
  if (this_request_is_for_own_identity) {
    raw_data = await make_authenticated_credential_pointer_request("GET", api_path, null, credentials);
  } else {
    const api_client = new OneIDAPIClient(credentials.api_base_url);
    raw_data = await api_client["_make_request"]("GET", api_path);
  }

  const raw_pointers = (raw_data.pointers ?? []) as Record<string, unknown>[];
  const pointers = raw_pointers.map(parse_pointer_from_api_response);

  return {
    agent_id: (raw_data.agent_id ?? agent_id) as string,
    pointers,
    pointer_count: (raw_data.pointer_count ?? pointers.length) as number,
    view: (raw_data.view ?? "public_only") as string,
  };
}

/**
 * Toggle a credential pointer between public and private visibility.
 *
 * @param pointer_id The pointer to update (prefix: cp-).
 * @param publicly_visible True to make public, False to make private.
 * @param credentials Optional pre-loaded credentials.
 * @returns The updated CredentialPointerInfo.
 */
export async function setCredentialPointerVisibility(
  pointer_id: string,
  publicly_visible: boolean,
  credentials?: StoredCredentials | null,
): Promise<CredentialPointerInfo> {
  const raw_data = await make_authenticated_credential_pointer_request(
    "PUT",
    `/api/v1/identity/credential-pointers/${pointer_id}/visibility`,
    { publicly_visible },
    credentials,
  );

  return parse_pointer_from_api_response(raw_data);
}

/**
 * Soft-delete a credential pointer.
 *
 * The pointer is marked as removed and no longer appears in list results.
 * The pointer is never hard-deleted, preserving the audit trail.
 *
 * @param pointer_id The pointer to remove (prefix: cp-).
 * @param credentials Optional pre-loaded credentials.
 * @returns The removed CredentialPointerInfo (with removed_at set).
 */
export async function removeCredentialPointer(
  pointer_id: string,
  credentials?: StoredCredentials | null,
): Promise<CredentialPointerInfo> {
  const raw_data = await make_authenticated_credential_pointer_request(
    "DELETE",
    `/api/v1/identity/credential-pointers/${pointer_id}`,
    null,
    credentials,
  );

  return parse_pointer_from_api_response(raw_data);
}
