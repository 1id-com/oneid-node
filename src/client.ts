/**
 * HTTP client for the 1id.com Enrollment API.
 *
 * Uses Node.js built-in `https`/`http` modules -- zero external dependencies.
 *
 * Handles all HTTP communication with the 1id.com server, including:
 * - Enrollment requests (declared and sovereign tiers)
 * - Identity lookups
 * - Handle management
 * - Error response mapping to SDK exceptions
 *
 * All responses follow the 1id.com API envelope:
 *   {"ok": true, "data": {...}, "error": null}
 *   {"ok": false, "data": null, "error": {"code": "...", "message": "..."}}
 */

import { SDK_USER_AGENT } from "./version.js";
import type { Token } from "./identity.js";
import { build_sender_constrained_request_headers } from "./airsHttpMessageSignatures.js";
import * as https from "node:https";
import * as http from "node:http";
import { DEFAULT_API_BASE_URL } from "./credentials.js";
import {
  EnrollmentError,
  NetworkError,
  raise_from_server_error_response,
} from "./exceptions.js";

// -- HTTP client configuration --
const DEFAULT_HTTP_TIMEOUT_MILLISECONDS = 30_000;
const USER_AGENT = SDK_USER_AGENT;

interface RequestOptions {
  method: string;
  path: string;
  json_body?: Record<string, unknown> | null;
  headers?: Record<string, string>;
  /** Sent sender-constrained: Authorization + an RFC 9421 signature by the enrolled key (OWN-038). */
  sender_constrained_token?: Token;
}

/**
 * Make a raw HTTP(S) request and return the parsed JSON body.
 * Uses only Node.js built-in modules.
 */
async function make_http_request(
  base_url: string,
  options: RequestOptions,
  timeout_milliseconds: number,
): Promise<{ status_code: number; body: unknown }> {
  const url = new URL(options.path, base_url);
  let request_headers: Record<string, string> = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json",
    ...options.headers,
  };
  let request_body_string: string | undefined;
  if (options.json_body != null) {
    request_body_string = JSON.stringify(options.json_body);
    request_headers["Content-Type"] = "application/json";
  }
  if (options.sender_constrained_token) {
    request_headers = await build_sender_constrained_request_headers(
      options.sender_constrained_token, options.method, url.href,
      request_body_string != null ? Buffer.from(request_body_string, "utf8") : null, request_headers);
  }
  if (request_body_string != null) {
    request_headers["Content-Length"] = Buffer.byteLength(request_body_string).toString();
  }
  return new Promise((resolve, reject) => {
    const is_https = url.protocol === "https:";
    const transport = is_https ? https : http;

    const req = transport.request(
      {
        hostname: url.hostname,
        port: url.port || (is_https ? 443 : 80),
        path: url.pathname + url.search,
        method: options.method,
        headers: request_headers,
        timeout: timeout_milliseconds,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => { chunks.push(chunk); });
        res.on("end", () => {
          const raw_body = Buffer.concat(chunks).toString("utf-8");
          try {
            const parsed_body = JSON.parse(raw_body);
            resolve({ status_code: res.statusCode ?? 0, body: parsed_body });
          } catch {
            reject(new NetworkError(
              `Invalid JSON response from ${url.href} (HTTP ${res.statusCode}): ${raw_body.slice(0, 200)}`
            ));
          }
        });
      },
    );

    req.on("error", (error: Error) => {
      reject(new NetworkError(`Could not connect to ${base_url}: ${error.message}`));
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new NetworkError(
        `Request to ${url.href} timed out after ${timeout_milliseconds}ms`
      ));
    });

    if (request_body_string != null) {
      req.write(request_body_string);
    }
    req.end();
  });
}

/**
 * HTTP client for the 1id.com enrollment and identity API.
 *
 * Wraps Node.js http/https with 1id-specific error handling. All methods
 * throw SDK exceptions on failure, never raw HTTP errors.
 */
export class OneIDAPIClient {
  public readonly api_base_url: string;
  public readonly timeout_milliseconds: number;

  constructor(
    api_base_url: string = DEFAULT_API_BASE_URL,
    timeout_milliseconds: number = DEFAULT_HTTP_TIMEOUT_MILLISECONDS,
  ) {
    this.api_base_url = api_base_url.replace(/\/+$/, "");
    this.timeout_milliseconds = timeout_milliseconds;
  }

  /**
   * Make an HTTP request to the 1id.com API and parse the envelope response.
   */
  private async _make_request(
    method: string,
    api_path: string,
    json_body?: Record<string, unknown> | null,
    headers?: Record<string, string>,
    sender_constrained_token?: Token,
  ): Promise<Record<string, unknown>> {
    const response = await make_http_request(
      this.api_base_url,
      { method, path: api_path, json_body, headers, sender_constrained_token },
      this.timeout_milliseconds,
    );

    const response_body = response.body as Record<string, unknown>;

    // Check for the standard 1id error envelope
    if (!response_body?.ok) {
      const error_info = (response_body?.error ?? {}) as Record<string, string>;
      const error_code = error_info.code ?? "UNKNOWN_ERROR";
      const error_message = error_info.message ?? `Server returned HTTP ${response.status_code}`;
      raise_from_server_error_response(error_code, error_message);
    }

    return (response_body.data ?? {}) as Record<string, unknown>;
  }

  /**
   * Enroll a new identity at the declared trust tier (no HSM required).
   */
  async enroll_declared(
    software_key_pem: string,
    key_algorithm: string,
    operator_email?: string | null,
    requested_handle?: string | null,
    display_name?: string | null,
    proof_of_possession_signature_b64?: string | null,
    proof_of_possession_signed_at_unix?: number | null,
  ): Promise<Record<string, unknown>> {
    const request_body: Record<string, unknown> = {
      software_key_pem,
      key_algorithm,
    };
    if (proof_of_possession_signature_b64 != null) {
      request_body["proof_of_possession_signature_b64"] = proof_of_possession_signature_b64;
      request_body["proof_of_possession_signed_at_unix"] = proof_of_possession_signed_at_unix;
    }
    if (operator_email != null) { request_body["operator_email"] = operator_email; }
    if (requested_handle != null) { request_body["requested_handle"] = requested_handle; }
    if (display_name != null) { request_body["display_name"] = display_name; }

    return this._make_request("POST", "/api/v1/enroll/declared", request_body);
  }

  /**
   * Begin TPM/HSM-based enrollment (sovereign/virtual tiers).
   */
  async enroll_begin(
    ek_certificate_pem: string,
    ak_public_key_pem: string,
    ak_tpmt_public_b64: string = "",
    ek_public_key_pem: string = "",
    ek_certificate_chain_pem?: string[],
    hsm_type: string = "tpm",
    operator_email?: string | null,
    requested_handle?: string | null,
    display_name?: string | null,
  ): Promise<Record<string, unknown>> {
    const request_body: Record<string, unknown> = {
      ek_certificate_pem,
      ek_public_key_pem,
      ak_public_key_pem,
      ak_tpmt_public_b64,
      hsm_type,
    };
    if (ek_certificate_chain_pem) { request_body["ek_certificate_chain_pem"] = ek_certificate_chain_pem; }
    if (operator_email != null) { request_body["operator_email"] = operator_email; }
    if (requested_handle != null) { request_body["requested_handle"] = requested_handle; }
    // OWN-029: the friendly name was dropped for TPM enrollment (Python sent it).
    if (display_name != null) { request_body["display_name"] = display_name; }

    return this._make_request("POST", "/api/v1/enroll/begin", request_body);
  }

  /**
   * Begin PIV-based enrollment (portable tier).
   *
   * Sends the PIV attestation certificate, chain, and signing public key
   * to the PIV-specific server endpoint. The server validates the chain
   * against the Yubico Root CA, checks the anti-Sybil registry by device
   * serial, and returns a nonce challenge for signature verification.
   */
  async enroll_begin_piv(
    attestation_cert_pem: string,
    attestation_chain_pem: string[],
    signing_key_public_pem: string,
    hsm_type: string = "yubikey",
    operator_email?: string | null,
    requested_handle?: string | null,
    display_name?: string | null,
  ): Promise<Record<string, unknown>> {
    const request_body: Record<string, unknown> = {
      attestation_cert_pem,
      attestation_chain_pem,
      signing_key_public_pem,
      hsm_type,
    };
    if (operator_email != null) { request_body["operator_email"] = operator_email; }
    if (requested_handle != null) { request_body["requested_handle"] = requested_handle; }
    // OWN-029: the friendly name was dropped for PIV enrollment (Python sent it).
    if (display_name != null) { request_body["display_name"] = display_name; }

    return this._make_request("POST", "/api/v1/enroll/begin/piv", request_body);
  }

  /**
   * Begin enclave enrollment by submitting the Secure Enclave public key.
   *
   * Server validates the P-256 key format, generates a nonce challenge,
   * and returns a session ID. The client signs the nonce with the Enclave
   * key and submits it to enroll_activate().
   */
  async enroll_begin_enclave(
    enclave_public_key_pem: string,
    operator_email?: string | null,
    requested_handle?: string | null,
    display_name?: string | null,
  ): Promise<Record<string, unknown>> {
    const request_body: Record<string, unknown> = {
      enclave_public_key_pem,
    };
    if (operator_email != null) { request_body["operator_email"] = operator_email; }
    if (requested_handle != null) { request_body["requested_handle"] = requested_handle; }
    if (display_name != null) { request_body["display_name"] = display_name; }

    return this._make_request("POST", "/api/v1/enroll/enclave/begin", request_body);
  }

  /**
   * Complete TPM/HSM-based enrollment by proving HSM possession.
   */
  async enroll_activate(
    enrollment_session_id: string,
    decrypted_credential: string | null = null,
    certify_info_b64: string | null = null,
    certify_signature_b64: string | null = null,
  ): Promise<Record<string, unknown>> {
    // TPM: certify_info + certify_signature from the import-and-certify proof
    // (no elevation). PIV/enclave: the nonce signature as decrypted_credential.
    const request_body: Record<string, unknown> = { enrollment_session_id };
    if (decrypted_credential != null) { request_body.decrypted_credential = decrypted_credential; }
    if (certify_info_b64 != null) {
      request_body.certify_info = certify_info_b64;
      request_body.certify_signature = certify_signature_b64;
    }
    return this._make_request("POST", "/api/v1/enroll/activate", request_body);
  }

  /**
   * "Welcome back": an already-enrolled TPM re-authenticates with a plain TPM
   * signature over a server nonce (no elevation). The identity is disclosed
   * only after the signature verifies.
   */
  async recover_begin_sign_based(
    ek_certificate_pem: string,
    ak_public_key_pem: string,
    ak_tpmt_public_b64: string = "",
    ek_public_key_pem: string = "",
    ek_certificate_chain_pem?: string[],
  ): Promise<Record<string, unknown>> {
    const request_body: Record<string, unknown> = {
      ek_certificate_pem,
      ak_public_key_pem,
      ak_tpmt_public_b64,
    };
    if (ek_public_key_pem) { request_body.ek_public_key_pem = ek_public_key_pem; }
    if (ek_certificate_chain_pem && ek_certificate_chain_pem.length > 0) {
      request_body.ek_certificate_chain_pem = ek_certificate_chain_pem;
    }
    return this._make_request("POST", "/api/v1/enroll/recover/sign-based", request_body);
  }

  async recover_activate_sign_based(
    recovery_session_id: string,
    signed_nonce_b64: string,
  ): Promise<Record<string, unknown>> {
    return this._make_request("POST", "/api/v1/enroll/recover/sign-based/activate", {
      enrollment_session_id: recovery_session_id,
      decrypted_credential: signed_nonce_b64,
    });
  }

  /**
   * Begin TPM-based identity recovery when credentials.json is lost
   * but the machine still has its original TPM. The server creates a
   * MakeCredential challenge to prove hardware possession and recover
   * the existing identity's credentials.
   */
  async recover_begin(
    ek_certificate_pem: string,
    ak_public_key_pem: string,
    ak_tpmt_public_b64: string = "",
    ek_public_key_pem: string = "",
    ek_certificate_chain_pem?: string[],
  ): Promise<Record<string, unknown>> {
    const request_body: Record<string, unknown> = {
      ek_certificate_pem,
      ak_public_key_pem,
      ak_tpmt_public_b64,
    };
    if (ek_public_key_pem) { request_body["ek_public_key_pem"] = ek_public_key_pem; }
    if (ek_certificate_chain_pem) { request_body["ek_certificate_chain_pem"] = ek_certificate_chain_pem; }

    return this._make_request("POST", "/api/v1/enroll/recover", request_body);
  }

  /**
   * Begin PIV-based identity recovery when credentials.json is lost
   * but the user still has their YubiKey/PIV device.
   */
  async recover_begin_piv(
    attestation_cert_pem: string,
    attestation_chain_pem: string[],
    signing_key_public_pem: string,
    hsm_type: string = "yubikey",
  ): Promise<Record<string, unknown>> {
    return this._make_request("POST", "/api/v1/enroll/recover/piv", {
      hsm_type,
      attestation_cert_pem,
      attestation_chain_pem,
      signing_key_public_pem,
    });
  }

  /**
   * Complete identity recovery by proving hardware possession.
   * Returns fresh credentials (rotated client_secret) for the
   * recovered identity.
   */
  async recover_activate(
    recovery_session_id: string,
    decrypted_credential: string,
  ): Promise<Record<string, unknown>> {
    return this._make_request("POST", "/api/v1/enroll/recover/activate", {
      enrollment_session_id: recovery_session_id,
      decrypted_credential,
    });
  }

  /**
   * Look up public identity information for an agent.
   */
  async get_identity(agent_id: string): Promise<Record<string, unknown>> {
    return this._make_request("GET", `/api/v1/identity/${agent_id}`);
  }

  /**
   * Check whether a vanity handle is available.
   */
  async check_handle_availability(handle_name: string): Promise<Record<string, unknown>> {
    return this._make_request("GET", `/api/v1/handle/${handle_name}`);
  }

  /**
   * Make an authenticated API request. The Token is sent sender-constrained:
   * Authorization + an RFC 9421 signature by the enrolled key over exactly this
   * request (registry-04 "HTTP Message Signatures", OWN-038). A bare access
   * token string cannot be used: 1id.com refuses bearer presentations.
   * Used by world/status, devices, lock-hardware, and operator-email endpoints.
   */
  async make_authenticated_request(
    method: string,
    api_path: string,
    token: Token,
    json_body?: Record<string, unknown> | null,
  ): Promise<Record<string, unknown>> {
    return this._make_request(method, api_path, json_body, undefined, token);
  }
}
