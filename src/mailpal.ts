/**
 * MailPal convenience functions for the 1id.com Node.js SDK.
 *
 *   import { send, activate, inbox, get_contact_token } from "1id/mailpal";
 *
 *   // One-call attested email sending
 *   const result = await send({
 *     to: ["recipient@example.com"],
 *     subject: "Hello from my AI agent",
 *     text_body: "Message body",
 *   });
 *
 *   // Account activation
 *   const account = await activate();
 *
 *   // Read inbox
 *   const messages = await inbox();
 *
 *   // Get contact token for email headers
 *   const token = await get_contact_token();
 *
 * Architecture (v2 -- local MIME assembly + direct SMTP):
 *
 *   send() builds the MIME message locally, extracts the exact wire-format
 *   bytes (including RFC 2047 encoding), computes attestation nonces from
 *   those bytes, injects attestation headers, then submits the fully-assembled
 *   message directly to smtp.mailpal.com via SMTP with STARTTLS + app_password.
 *
 *   This guarantees the SDK signs the same byte-for-byte header values that the
 *   receiving milter will verify, eliminating canonicalization mismatches.
 */

import * as net from "node:net";
import * as tls from "node:tls";
import * as crypto from "node:crypto";
import * as https from "node:https";
import * as http from "node:http";
import { get_token } from "./auth.js";
import { type StoredCredentials, load_credentials, save_credentials } from "./credentials.js";
import {
  prepareAttestation,
  prepare_direct_hardware_attestation,
  type AttestationProof,
  type DirectAttestationProof,
} from "./attestation.js";
import { AuthenticationError, NetworkError, NotEnrolledError } from "./exceptions.js";

const _MAILPAL_API_BASE_URL = "https://mailpal.com";
const _HTTP_TIMEOUT_MILLISECONDS = 30_000;
const _USER_AGENT = "oneid-sdk-node/1.1.0";
const _SMTP_HOST = "smtp.mailpal.com";
const _SMTP_PORT_STARTTLS = 587;
const _SMTP_TIMEOUT_MILLISECONDS = 30_000;


// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface SendResult {
  message_id: string;
  from_address: string;
  attestation_headers_included: boolean;
  contact_token_header_included: boolean;
  sd_jwt_header_included: boolean;
  direct_attestation_header_included: boolean;
}

export interface MailpalAccount {
  _type: "account";
  primary_email: string;
  vanity_email: string | null;
  app_password: string | null;
  already_existed: boolean;
  smtp: Record<string, unknown> | null;
  imap: Record<string, unknown> | null;
}

export interface MailpalActivationChallenge {
  _type: "challenge";
  challenge_token: string;
  prompt: string;
  difficulty: string;
  expires_in_seconds: number;
  attempt_limit: number;
}

export interface InboxMessage {
  message_id: string;
  from_address: string;
  subject: string;
  received_at: string;
  is_unread: boolean;
}


// ---------------------------------------------------------------------------
// Options types
// ---------------------------------------------------------------------------

export interface SendOptions {
  to: string[];
  subject: string;
  text_body?: string | null;
  html_body?: string | null;
  from_address?: string | null;
  from_display_name?: string | null;
  cc?: string[] | null;
  bcc?: string[] | null;
  include_attestation?: boolean;
  attestation_mode?: "both" | "sd-jwt" | "direct" | "none";
  disclosed_claims?: string[] | null;
  oneid_api_url?: string | null;
  smtp_host?: string | null;
  smtp_port?: number | null;
}

export interface ActivateOptions {
  challenge_token?: string | null;
  challenge_answer?: string | null;
  display_name?: string | null;
  mailpal_api_url?: string | null;
}

export interface InboxOptions {
  limit?: number;
  offset?: number;
  unread_only?: boolean;
  mailpal_api_url?: string | null;
}


// ---------------------------------------------------------------------------
// Internal HTTP helper
// ---------------------------------------------------------------------------

interface MailpalHttpResponse {
  status_code: number;
  body: Record<string, unknown> | null;
  raw: string;
}

function _make_mailpal_http_request(
  method: string,
  url_string: string,
  body_json: Record<string, unknown> | null,
  auth_headers: Record<string, string>,
  timeout_milliseconds: number = _HTTP_TIMEOUT_MILLISECONDS,
): Promise<MailpalHttpResponse> {
  return new Promise((resolve, reject) => {
    const url = new URL(url_string);
    const is_https = url.protocol === "https:";
    const transport = is_https ? https : http;

    const request_headers: Record<string, string> = {
      "User-Agent": _USER_AGENT,
      "Accept": "application/json",
      ...auth_headers,
    };

    let request_body_string: string | undefined;
    if (body_json != null) {
      request_body_string = JSON.stringify(body_json);
      request_headers["Content-Type"] = "application/json";
      request_headers["Content-Length"] = Buffer.byteLength(request_body_string).toString();
    }

    const req = transport.request({
      hostname: url.hostname,
      port: url.port || (is_https ? 443 : 80),
      path: url.pathname + url.search,
      method,
      headers: request_headers,
      timeout: timeout_milliseconds,
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => { chunks.push(chunk); });
      res.on("end", () => {
        const raw_body = Buffer.concat(chunks).toString("utf-8");
        try {
          const parsed_body = JSON.parse(raw_body) as Record<string, unknown>;
          resolve({ status_code: res.statusCode ?? 0, body: parsed_body, raw: raw_body });
        } catch {
          resolve({ status_code: res.statusCode ?? 0, body: null, raw: raw_body });
        }
      });
    });

    req.on("error", (error: Error) => {
      reject(new NetworkError(`Could not connect to MailPal: ${error.message}`));
    });
    req.on("timeout", () => {
      req.destroy();
      reject(new NetworkError(`MailPal request timed out after ${timeout_milliseconds}ms`));
    });

    if (request_body_string != null) {
      req.write(request_body_string);
    }
    req.end();
  });
}


async function _get_bearer_auth_headers(): Promise<Record<string, string>> {
  const token = await get_token();
  return { "Authorization": `Bearer ${token.access_token}` };
}


// ---------------------------------------------------------------------------
// RFC 2047 / MIME helpers
// ---------------------------------------------------------------------------

function _encode_as_rfc2047_base64_if_non_ascii(text: string): string {
  if (/^[\x20-\x7e]*$/.test(text)) { return text; }
  return "=?utf-8?b?" + Buffer.from(text, "utf-8").toString("base64") + "?=";
}

function _format_email_address_with_optional_display_name(
  display_name: string,
  email_address: string,
): string {
  if (!display_name) { return email_address; }
  return `${_encode_as_rfc2047_base64_if_non_ascii(display_name)} <${email_address}>`;
}

function _parse_address_into_name_and_email(
  address_string: string,
): { display_name: string; email: string } {
  const angle_bracket_match = address_string.match(/^(?:"?([^"<]*)"?\s*)?<([^>]+)>$/);
  if (angle_bracket_match) {
    return {
      display_name: (angle_bracket_match[1] ?? "").trim(),
      email: (angle_bracket_match[2] ?? "").trim(),
    };
  }
  return { display_name: "", email: address_string.trim() };
}

function _extract_bare_email_from_address_string(address_string: string): string {
  return _parse_address_into_name_and_email(address_string).email;
}

function _format_rfc2822_date_for_current_moment(): string {
  const d = new Date();
  const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const offset_total_minutes = -d.getTimezoneOffset();
  const sign = offset_total_minutes >= 0 ? "+" : "-";
  const abs_offset = Math.abs(offset_total_minutes);
  const hours_part = String(Math.floor(abs_offset / 60)).padStart(2, "0");
  const minutes_part = String(abs_offset % 60).padStart(2, "0");
  return `${days[d.getDay()]}, ${String(d.getDate()).padStart(2, "0")} ${months[d.getMonth()]} ` +
    `${d.getFullYear()} ${String(d.getHours()).padStart(2, "0")}:` +
    `${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")} ` +
    `${sign}${hours_part}${minutes_part}`;
}

function _generate_unique_message_id_for_mailpal_domain(): string {
  const timestamp = Date.now();
  const random_hex = crypto.randomBytes(8).toString("hex");
  return `<${timestamp}.${random_hex}@mailpal.com>`;
}

function _build_mime_message_as_wire_format_bytes(
  ordered_headers: Array<[string, string]>,
  body_text: string,
): Buffer {
  const header_lines = ordered_headers.map(([name, value]) => `${name}: ${value}`);
  header_lines.push('Content-Type: text/plain; charset="utf-8"');
  header_lines.push("Content-Transfer-Encoding: 7bit");
  header_lines.push("MIME-Version: 1.0");
  const header_section = header_lines.join("\r\n");
  return Buffer.from(header_section + "\r\n\r\n" + body_text + "\r\n", "utf-8");
}

function _extract_wire_format_headers_from_raw_bytes(
  wire_bytes: Buffer,
): Record<string, string> {
  const separator_index = wire_bytes.indexOf("\r\n\r\n");
  if (separator_index < 0) { return {}; }
  const header_section = wire_bytes.subarray(0, separator_index).toString("utf-8");
  const headers: Record<string, string> = {};
  let current_name: string | null = null;
  let current_value = "";
  for (const line of header_section.split("\r\n")) {
    if (line.startsWith(" ") || line.startsWith("\t")) {
      if (current_name) { current_value += " " + line.trim(); }
    } else {
      if (current_name) { headers[current_name.toLowerCase()] = current_value; }
      const colon_pos = line.indexOf(":");
      if (colon_pos > 0) {
        current_name = line.substring(0, colon_pos);
        current_value = line.substring(colon_pos + 1).trim();
      }
    }
  }
  if (current_name) { headers[current_name.toLowerCase()] = current_value; }
  return headers;
}

function _extract_body_bytes_from_wire_format(wire_bytes: Buffer): Buffer {
  const separator_index = wire_bytes.indexOf("\r\n\r\n");
  if (separator_index < 0) { return Buffer.alloc(0); }
  return wire_bytes.subarray(separator_index + 4);
}

function _fold_long_header_value_for_smtp_transmission(
  header_name: string,
  header_value: string,
): string {
  const full_line = `${header_name}: ${header_value}`;
  if (full_line.length <= 76) { return full_line; }
  const first_line = full_line.substring(0, 76);
  let remaining = full_line.substring(76);
  const lines = [first_line];
  while (remaining.length > 0) {
    const chunk = remaining.substring(0, 75);
    lines.push(" " + chunk);
    remaining = remaining.substring(75);
  }
  return lines.join("\r\n");
}

function _inject_attestation_headers_into_wire_bytes(
  wire_bytes: Buffer,
  attestation_header_lines: string[],
): Buffer {
  if (attestation_header_lines.length === 0) { return wire_bytes; }
  const separator_index = wire_bytes.indexOf("\r\n\r\n");
  if (separator_index < 0) { return wire_bytes; }
  const headers_section = wire_bytes.subarray(0, separator_index);
  const body_and_separator_tail = wire_bytes.subarray(separator_index);
  const injected_bytes = Buffer.from("\r\n" + attestation_header_lines.join("\r\n"), "utf-8");
  return Buffer.concat([headers_section, injected_bytes, body_and_separator_tail]);
}


// ---------------------------------------------------------------------------
// SMTP client with STARTTLS (raw TCP → TLS upgrade, AUTH PLAIN)
// ---------------------------------------------------------------------------

function _send_raw_message_via_smtp_with_starttls(
  host: string,
  port: number,
  auth_email: string,
  auth_password: string,
  envelope_from: string,
  envelope_to_list: string[],
  message_bytes: Buffer,
  timeout_ms: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port, timeout: timeout_ms });
    let secure_socket: tls.TLSSocket | null = null;
    let command_queue: string[] = [];
    let response_buffer = "";
    let phase = "greeting";

    function on_smtp_data(data: Buffer): void {
      response_buffer += data.toString("utf-8");
      while (response_buffer.includes("\r\n")) {
        const line_end = response_buffer.indexOf("\r\n");
        const line = response_buffer.substring(0, line_end);
        response_buffer = response_buffer.substring(line_end + 2);
        const code = parseInt(line.substring(0, 3), 10);
        const is_continuation = line[3] === "-";
        if (!is_continuation) { handle_smtp_response_line(code, line); }
      }
    }

    function send_smtp_command(cmd: string): void {
      const active_socket = secure_socket ?? socket;
      active_socket.write(cmd + "\r\n");
    }

    function handle_smtp_response_line(code: number, line: string): void {
      if (phase === "greeting") {
        if (code !== 220) { return reject(new NetworkError(`SMTP greeting failed: ${line}`)); }
        phase = "ehlo1";
        send_smtp_command("EHLO oneid-sdk");
      } else if (phase === "ehlo1") {
        if (code !== 250) { return reject(new NetworkError(`SMTP EHLO failed: ${line}`)); }
        phase = "starttls";
        send_smtp_command("STARTTLS");
      } else if (phase === "starttls") {
        if (code !== 220) { return reject(new NetworkError(`SMTP STARTTLS failed: ${line}`)); }
        phase = "tls_upgrade";
        secure_socket = tls.connect(
          { socket, servername: host, rejectUnauthorized: true },
          () => {
            phase = "ehlo2";
            secure_socket!.on("data", on_smtp_data);
            socket.removeAllListeners("data");
            send_smtp_command("EHLO oneid-sdk");
          },
        );
        secure_socket.on("error", (err) => {
          reject(new NetworkError(`SMTP TLS error: ${err.message}`));
        });
      } else if (phase === "ehlo2") {
        if (code !== 250) { return reject(new NetworkError(`SMTP EHLO after TLS failed: ${line}`)); }
        phase = "auth";
        const auth_string = Buffer.from(`\x00${auth_email}\x00${auth_password}`).toString("base64");
        send_smtp_command(`AUTH PLAIN ${auth_string}`);
      } else if (phase === "auth") {
        if (code !== 235) { return reject(new AuthenticationError(`SMTP authentication failed: ${line}`)); }
        phase = "mail_from";
        send_smtp_command(`MAIL FROM:<${envelope_from}>`);
      } else if (phase === "mail_from") {
        if (code !== 250) { return reject(new NetworkError(`SMTP MAIL FROM failed: ${line}`)); }
        phase = "rcpt_to";
        command_queue = [...envelope_to_list];
        send_smtp_command(`RCPT TO:<${command_queue.shift()!}>`);
      } else if (phase === "rcpt_to") {
        if (code !== 250) { return reject(new NetworkError(`SMTP RCPT TO failed: ${line}`)); }
        if (command_queue.length > 0) {
          send_smtp_command(`RCPT TO:<${command_queue.shift()!}>`);
        } else {
          phase = "data_cmd";
          send_smtp_command("DATA");
        }
      } else if (phase === "data_cmd") {
        if (code !== 354) { return reject(new NetworkError(`SMTP DATA command failed: ${line}`)); }
        phase = "data_done";
        const active_socket = secure_socket ?? socket;
        active_socket.write(message_bytes);
        active_socket.write(Buffer.from("\r\n.\r\n"));
      } else if (phase === "data_done") {
        if (code !== 250) { return reject(new NetworkError(`SMTP message rejected: ${line}`)); }
        phase = "quit";
        send_smtp_command("QUIT");
      } else if (phase === "quit") {
        const active_socket = secure_socket ?? socket;
        active_socket.destroy();
        resolve();
      }
    }

    socket.on("data", on_smtp_data);
    socket.on("error", (err) => {
      reject(new NetworkError(`SMTP connection error: ${err.message}`));
    });
    socket.on("timeout", () => {
      socket.destroy();
      reject(new NetworkError("SMTP connection timed out"));
    });
  });
}


// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Activate a MailPal account for the current 1id identity.
 *
 * Two-phase flow:
 *   Phase 1 -- call activate() with no args → returns MailpalActivationChallenge
 *   Phase 2 -- call activate({ challenge_token, challenge_answer }) → returns MailpalAccount
 *   If already activated, Phase 1 returns MailpalAccount directly (idempotent).
 *
 * On success, persists mailpal_email and app_password to credentials.json.
 */
export async function activate(
  options?: ActivateOptions,
): Promise<MailpalAccount | MailpalActivationChallenge> {
  const {
    challenge_token = null,
    challenge_answer = null,
    display_name = null,
    mailpal_api_url = null,
  } = options ?? {};

  const url = `${mailpal_api_url ?? _MAILPAL_API_BASE_URL}/api/v1/activate`;

  const request_body: Record<string, unknown> = {};
  if (challenge_token && challenge_answer) {
    request_body["challenge_token"] = challenge_token;
    request_body["challenge_answer"] = challenge_answer;
  }
  if (display_name) {
    request_body["display_name"] = display_name;
  }

  const auth_headers = await _get_bearer_auth_headers();
  const has_body = Object.keys(request_body).length > 0;

  const response = await _make_mailpal_http_request(
    "POST", url, has_body ? request_body : null, auth_headers,
  );

  if (response.status_code === 401) {
    throw new AuthenticationError("Bearer token rejected by MailPal.");
  }
  if (response.status_code === 403) {
    const error_info = (response.body?.["error"] ?? {}) as Record<string, string>;
    throw new AuthenticationError(
      `Challenge failed: ${error_info["message"] ?? response.raw.slice(0, 200)}. ` +
      "Call activate() again with no arguments to get a new challenge."
    );
  }
  if (response.status_code === 429) {
    const error_info = (response.body?.["error"] ?? {}) as Record<string, string>;
    throw new NetworkError(`Rate limited: ${error_info["message"] ?? response.raw.slice(0, 200)}`);
  }
  if (response.status_code !== 200 && response.status_code !== 201) {
    throw new NetworkError(
      `MailPal activate failed (HTTP ${response.status_code}): ${response.raw.slice(0, 200)}`,
    );
  }

  const data = (response.body?.["data"] ?? {}) as Record<string, unknown>;

  if (data["phase"] === "challenge") {
    return {
      _type: "challenge" as const,
      challenge_token: (data["challenge_token"] as string) ?? "",
      prompt: (data["prompt"] as string) ?? "",
      difficulty: (data["difficulty"] as string) ?? "easy",
      expires_in_seconds: (data["expires_in_seconds"] as number) ?? 300,
      attempt_limit: (data["attempt_limit"] as number) ?? 3,
    };
  }

  const account: MailpalAccount = {
    _type: "account" as const,
    primary_email: (data["primary_email"] as string) ?? "",
    vanity_email: (data["vanity_email"] as string) ?? null,
    app_password: (data["app_password"] as string) ?? null,
    already_existed: (data["already_activated"] as boolean) ?? false,
    smtp: (data["smtp"] as Record<string, unknown>) ?? null,
    imap: (data["imap"] as Record<string, unknown>) ?? null,
  };

  if (account.primary_email) {
    try {
      const creds = load_credentials();
      let mailpal_credentials_changed = false;
      if (creds.mailpal_email !== account.primary_email) {
        creds.mailpal_email = account.primary_email;
        mailpal_credentials_changed = true;
      }
      if (account.app_password && creds.mailpal_app_password !== account.app_password) {
        creds.mailpal_app_password = account.app_password;
        mailpal_credentials_changed = true;
      }
      if (mailpal_credentials_changed) {
        save_credentials(creds);
      }
    } catch {
      /* best-effort credential persistence */
    }
  }

  return account;
}


/**
 * Send an attested email via direct SMTP submission to smtp.mailpal.com.
 *
 * Builds the MIME message locally, computes attestation from the exact
 * wire-format bytes (guaranteeing the milter verifies the same bytes),
 * injects attestation headers, and submits via SMTP with STARTTLS.
 *
 * @param options.to - Recipient addresses (To header).
 * @param options.subject - Email subject line.
 * @param options.text_body - Plain text body.
 * @param options.from_address - Sender email (default: stored mailpal_email).
 * @param options.from_display_name - Override display name for From header.
 * @param options.cc - Cc recipients.
 * @param options.bcc - Bcc recipients (hidden from headers).
 * @param options.attestation_mode - "both" | "sd-jwt" | "direct" | "none".
 * @param options.disclosed_claims - SD-JWT claims to disclose (default: ["trust_tier"]).
 */
export async function send(options: SendOptions): Promise<SendResult> {
  const {
    to,
    subject,
    text_body = null,
    html_body = null,
    from_address = null,
    from_display_name = null,
    cc = null,
    bcc = null,
    include_attestation = true,
    attestation_mode = "both",
    disclosed_claims = null,
    oneid_api_url = null,
    smtp_host = null,
    smtp_port = null,
  } = options;

  const creds = load_credentials();

  const smtp_auth_email = creds.mailpal_email ?? `${creds.client_id}@mailpal.com`;
  const smtp_auth_password = creds.mailpal_app_password;
  if (!smtp_auth_password) {
    throw new NotEnrolledError(
      "No MailPal app_password found in stored credentials. " +
      "Call mailpal.activate() first to create a MailPal account " +
      "and store SMTP credentials, or manually add mailpal_app_password " +
      "to credentials.json."
    );
  }

  const parsed_from = _parse_address_into_name_and_email(from_address ?? "");
  const effective_from_email = parsed_from.email || smtp_auth_email;
  const effective_from_display_name =
    from_display_name ?? parsed_from.display_name ?? creds.display_name ?? "";

  const effective_include_attestation = attestation_mode === "none" ? false : include_attestation;

  // -- Phase 1: Build MIME message locally --
  const message_id = _generate_unique_message_id_for_mailpal_domain();
  const date_header = _format_rfc2822_date_for_current_moment();
  const from_header_value = _format_email_address_with_optional_display_name(
    effective_from_display_name, effective_from_email,
  );

  const ordered_mime_headers: Array<[string, string]> = [
    ["From", from_header_value],
    ["To", to.join(", ")],
    ["Subject", subject],
    ["Date", date_header],
    ["Message-ID", message_id],
  ];
  if (cc && cc.length > 0) {
    ordered_mime_headers.push(["Cc", cc.join(", ")]);
  }

  const effective_body = text_body ?? html_body ?? "";
  const wire_format_message_bytes = _build_mime_message_as_wire_format_bytes(
    ordered_mime_headers, effective_body,
  );

  // -- Phase 2: Extract wire-format headers (same as milter would parse) --
  const wire_format_headers = _extract_wire_format_headers_from_raw_bytes(
    wire_format_message_bytes,
  );
  const wire_format_body_bytes = _extract_body_bytes_from_wire_format(
    wire_format_message_bytes,
  );

  const _MODE2_REQUIRED_HEADER_NAMES = new Set(["from", "to", "subject", "date", "message-id"]);
  const wire_format_headers_for_mode2_nonce: Record<string, string> = {};
  for (const [key, value] of Object.entries(wire_format_headers)) {
    if (_MODE2_REQUIRED_HEADER_NAMES.has(key)) {
      wire_format_headers_for_mode2_nonce[key] = value;
    }
  }

  // -- Phase 3: Compute attestation from wire-format bytes --
  let mode2_sd_jwt_proof: AttestationProof | null = null;
  let mode1_direct_attestation_proof: DirectAttestationProof | null = null;
  const include_sd_jwt_mode = attestation_mode === "sd-jwt" || attestation_mode === "both";
  const include_direct_mode = attestation_mode === "direct" || attestation_mode === "both";

  if (effective_include_attestation && include_sd_jwt_mode) {
    try {
      mode2_sd_jwt_proof = await prepareAttestation({
        emailHeaders: wire_format_headers_for_mode2_nonce,
        body: wire_format_body_bytes,
        disclosedClaims: disclosed_claims ?? undefined,
        apiBaseUrl: oneid_api_url ?? undefined,
      });
    } catch (attestation_error) {
      console.warn(`[oneid.mailpal] Mode 2 (SD-JWT) attestation failed: ${attestation_error}`);
    }
  }

  if (effective_include_attestation && include_direct_mode) {
    try {
      mode1_direct_attestation_proof = await prepare_direct_hardware_attestation(
        wire_format_headers, wire_format_body_bytes,
      );
    } catch (mode1_error) {
      console.warn(`[oneid.mailpal] Mode 1 (Direct Hardware) attestation failed: ${mode1_error}`);
    }
  }

  // -- Phase 4: Build attestation header lines --
  const attestation_header_lines_to_inject: string[] = [];

  if (mode1_direct_attestation_proof?.hardware_attestation_header_value) {
    attestation_header_lines_to_inject.push(
      _fold_long_header_value_for_smtp_transmission(
        "Hardware-Attestation",
        mode1_direct_attestation_proof.hardware_attestation_header_value,
      ),
    );
  }

  if (mode2_sd_jwt_proof) {
    if (mode2_sd_jwt_proof.sd_jwt) {
      let sd_jwt_presentation_value = mode2_sd_jwt_proof.sd_jwt;
      if (mode2_sd_jwt_proof.sd_jwt_disclosures &&
          Object.keys(mode2_sd_jwt_proof.sd_jwt_disclosures).length > 0) {
        for (const disclosure_b64url of Object.values(mode2_sd_jwt_proof.sd_jwt_disclosures)) {
          sd_jwt_presentation_value += "~" + disclosure_b64url;
        }
        sd_jwt_presentation_value += "~";
      }
      attestation_header_lines_to_inject.push(
        _fold_long_header_value_for_smtp_transmission(
          "Hardware-Trust-Proof", sd_jwt_presentation_value,
        ),
      );
    }
    if (mode2_sd_jwt_proof.contact_token) {
      attestation_header_lines_to_inject.push(
        `X-1ID-Contact-Token: ${mode2_sd_jwt_proof.contact_token}`,
      );
    }
  }

  // -- Phase 5: Inject attestation headers --
  const final_message_bytes = _inject_attestation_headers_into_wire_bytes(
    wire_format_message_bytes, attestation_header_lines_to_inject,
  );

  // -- Phase 6: Submit via SMTP with STARTTLS --
  const effective_smtp_host = smtp_host ?? _SMTP_HOST;
  const effective_smtp_port = smtp_port ?? _SMTP_PORT_STARTTLS;

  const all_recipient_emails: string[] = [];
  for (const addr of to) { all_recipient_emails.push(_extract_bare_email_from_address_string(addr)); }
  if (cc) { for (const addr of cc) { all_recipient_emails.push(_extract_bare_email_from_address_string(addr)); } }
  if (bcc) { for (const addr of bcc) { all_recipient_emails.push(_extract_bare_email_from_address_string(addr)); } }

  if (all_recipient_emails.length === 0) {
    throw new Error("No valid recipient email addresses found in to/cc/bcc.");
  }

  await _send_raw_message_via_smtp_with_starttls(
    effective_smtp_host, effective_smtp_port,
    smtp_auth_email, smtp_auth_password,
    smtp_auth_email, all_recipient_emails,
    final_message_bytes, _SMTP_TIMEOUT_MILLISECONDS,
  );

  return {
    message_id,
    from_address: effective_from_email,
    attestation_headers_included: mode2_sd_jwt_proof != null || mode1_direct_attestation_proof != null,
    contact_token_header_included: mode2_sd_jwt_proof?.contact_token != null,
    sd_jwt_header_included: mode2_sd_jwt_proof?.sd_jwt != null,
    direct_attestation_header_included: mode1_direct_attestation_proof?.hardware_attestation_header_value != null,
  };
}


/**
 * Fetch inbox messages from MailPal.
 *
 * @param options.limit - Max messages to return (default 20).
 * @param options.offset - Pagination offset.
 * @param options.unread_only - If true, only return unread messages.
 */
export async function inbox(options?: InboxOptions): Promise<InboxMessage[]> {
  const {
    limit = 20,
    offset = 0,
    unread_only = false,
    mailpal_api_url = null,
  } = options ?? {};

  let url = `${mailpal_api_url ?? _MAILPAL_API_BASE_URL}/api/v1/inbox?limit=${limit}&offset=${offset}`;
  if (unread_only) { url += "&unread_only=true"; }

  const auth_headers = await _get_bearer_auth_headers();
  const response = await _make_mailpal_http_request("GET", url, null, auth_headers);

  if (response.status_code === 401) {
    throw new AuthenticationError("Bearer token rejected by MailPal.");
  }
  if (response.status_code !== 200) {
    throw new NetworkError(
      `MailPal inbox failed (HTTP ${response.status_code}): ${response.raw.slice(0, 200)}`,
    );
  }

  const data = (response.body?.["data"] ?? {}) as Record<string, unknown>;
  const messages_raw = (data["messages"] ?? []) as Array<Record<string, unknown>>;

  return messages_raw.map((msg) => ({
    message_id: (msg["id"] as string) ?? "",
    from_address: (msg["from"] as string) ?? "",
    subject: (msg["subject"] as string) ?? "",
    received_at: (msg["received_at"] as string) ?? "",
    is_unread: (msg["is_unread"] as boolean) ?? true,
  }));
}


/**
 * Get the current contact token for use in email headers.
 *
 * Returns the bare token string or null if unavailable.
 */
export async function get_contact_token(
  oneid_api_url?: string | null,
): Promise<string | null> {
  const creds = load_credentials();
  const api_base_url = oneid_api_url ?? creds.api_base_url ?? "https://1id.com";

  const token = await get_token();
  const auth_headers: Record<string, string> = {
    "Authorization": `Bearer ${token.access_token}`,
    "User-Agent": _USER_AGENT,
  };

  const url = `${api_base_url}/api/v1/contact-token`;
  const response = await _make_mailpal_http_request("GET", url, null, auth_headers);

  if (response.status_code !== 200) { return null; }

  const data = (response.body?.["data"] ?? {}) as Record<string, unknown>;
  return (data["token"] as string) ?? null;
}
