/**
 * AIRS proof-of-possession for HTTP requests: the RFC 9421 HTTP Message
 * Signatures profile of draft-drake-agent-identity-registry-04 "HTTP Message
 * Signatures" (sender-constrained tokens; review 072 / OWN-038).
 *
 * CROSS_IMPL_SYNC: airs_http_message_signatures
 * Implementations: py:oneid/airs_http_message_signatures.py node:src/airsHttpMessageSignatures.ts
 *
 * An AIRS access token carries cnf.jwk: the public key of the enrolled
 * hardware (or declared software) key that authenticated when it was issued.
 * Every request presenting the token also carries a fresh signature by that
 * key over the request, so a stolen token is useless without the hardware.
 *
 * Profile: label "airs"; covered components in order "@method",
 * "@target-uri", "authorization", then "content-digest" (RFC 9530, checked
 * against the received bytes) when there is content and "content-type" when
 * present; parameters created, nonce (>= 96 bits), tag="airs-pop", and keyid
 * = the RFC 7638 thumbprint of cnf.jwk (never used to pick another key);
 * 60 s maximum age plus clock skew; replayed nonces rejected; RSASSA-PKCS1-v1_5
 * SHA-256 (TPM attestation keys), ECDSA P-256 SHA-256 as r||s (PIV, Secure
 * Enclave, declared), Ed25519.
 *
 * sign_request / fetch_with_airs_proof_of_possession are for agents (the SDK
 * signs every authenticated call); verify_request is for relying parties.
 */

import * as crypto from "node:crypto";

export const AIRS_SIGNATURE_LABEL = "airs";
export const AIRS_SIGNATURE_TAG = "airs-pop";
export const MAXIMUM_SIGNATURE_AGE_SECONDS = 60;
// registry-04: 60 s plus a small clock-skew allowance. Agents' clocks drift (a Windows
// host was 11 s fast on 2026-09-25); the SDK corrects with the token's server-issued
// iat, and relying parties allow 30 s for clients that do not.
export const ALLOWED_CLOCK_SKEW_SECONDS = 30;
export const MINIMUM_NONCE_BITS = 96;
const REQUIRED_COVERED_COMPONENTS = ["@method", "@target-uri", "authorization"];

/** Signs an RFC 9421 signature base with the token's confirmation key. */
export type AirsRequestSigner = (signature_base: Buffer) => Promise<Buffer>;
export type ConfirmationJwk = Record<string, string>;

export class AirsHttpMessageSignatureRejected extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AirsHttpMessageSignatureRejected";
  }
}

// ---------------------------------------------------------------------------
// Content-Digest (RFC 9530), parameters, signature base (RFC 9421 s2.5)
// ---------------------------------------------------------------------------

export function compute_content_digest_header_value_for_request_body(body: Buffer): string {
  return `sha-256=:${crypto.createHash("sha256").update(body).digest("base64")}:`;
}

function content_digest_matches_body(content_digest_header_value: string, body: Buffer): boolean {
  for (const member of content_digest_header_value.split(",")) {
    const separator = member.indexOf("=");
    if (separator < 0) { continue; }
    if (member.slice(0, separator).trim().toLowerCase() !== "sha-256") { continue; }
    const value = member.slice(separator + 1).trim();
    if (value.length < 2 || value[0] !== ":" || value[value.length - 1] !== ":") { return false; }
    const expected = crypto.createHash("sha256").update(body).digest();
    const received = Buffer.from(value.slice(1, -1), "base64");
    return received.length === expected.length && crypto.timingSafeEqual(received, expected);
  }
  return false;
}

export function compute_rfc7638_jwk_sha256_thumbprint(jwk: ConfirmationJwk): string {
  const required_members: Record<string, string[]> = {
    RSA: ["e", "kty", "n"], EC: ["crv", "kty", "x", "y"], OKP: ["crv", "kty", "x"],
  };
  const members = required_members[jwk.kty];
  if (!members) {
    throw new AirsHttpMessageSignatureRejected(`cannot thumbprint JWK key type ${jwk.kty}`);
  }
  const canonical = "{" + members.map((name) => `${JSON.stringify(name)}:${JSON.stringify(jwk[name])}`).join(",") + "}";
  return crypto.createHash("sha256").update(canonical, "utf8").digest("base64url");
}

export function serialize_airs_signature_parameters(
  covered_component_names: string[], created: number, nonce: string, keyid?: string | null,
): string {
  let serialized = `(${covered_component_names.map((name) => `"${name}"`).join(" ")})`
    + `;created=${created};nonce="${nonce}";tag="${AIRS_SIGNATURE_TAG}"`;
  if (keyid) { serialized += `;keyid="${keyid}"`; }
  return serialized;
}

export function build_airs_signature_base(
  covered_component_values: Array<[string, string]>, serialized_signature_parameters: string,
): Buffer {
  const lines = covered_component_values.map(([name, value]) => `"${name}": ${value}`);
  lines.push(`"@signature-params": ${serialized_signature_parameters}`);
  return Buffer.from(lines.join("\n"), "utf8");
}

function lowercase_header_map(headers: Record<string, string>): Record<string, string> {
  const lowered: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) { lowered[name.toLowerCase()] = value; }
  return lowered;
}

// ---------------------------------------------------------------------------
// Signature encodings
// ---------------------------------------------------------------------------

/** ECDSA-Sig-Value DER -> RFC 9421 raw r||s (PIV and the Secure Enclave return DER). */
export function convert_der_ecdsa_signature_to_rfc9421_raw_r_and_s(der_signature: Buffer, coordinate_octets = 32): Buffer {
  let offset = 0;
  const read_length = (): number => {
    let length = der_signature[offset++];
    if (length & 0x80) {
      const octets = length & 0x7f;
      length = 0;
      for (let i = 0; i < octets; i++) { length = (length << 8) | der_signature[offset++]; }
    }
    return length;
  };
  if (der_signature[offset++] !== 0x30) { throw new Error("ECDSA signature is not a DER SEQUENCE"); }
  const sequence_length = read_length();
  if (offset + sequence_length !== der_signature.length) { throw new Error("ECDSA DER signature has trailing or missing octets"); }
  const read_integer = (): Buffer => {
    if (der_signature[offset++] !== 0x02) { throw new Error("ECDSA DER signature: INTEGER expected"); }
    const length = read_length();
    let value = der_signature.subarray(offset, offset + length);
    offset += length;
    while (value.length > coordinate_octets && value[0] === 0) { value = value.subarray(1); }
    if (value.length > coordinate_octets) { throw new Error("ECDSA DER integer too long for the curve"); }
    return Buffer.concat([Buffer.alloc(coordinate_octets - value.length), value]);
  };
  const r = read_integer();
  const s = read_integer();
  if (offset !== der_signature.length) { throw new Error("ECDSA DER signature has trailing octets"); }
  return Buffer.concat([r, s]);
}

// ---------------------------------------------------------------------------
// Signing (agents)
// ---------------------------------------------------------------------------

export async function sign_request(
  method: string,
  target_uri: string,
  headers: Record<string, string>,
  body: Buffer | null,
  sign_signature_base_with_confirmation_key: AirsRequestSigner,
  options: { created?: number; nonce?: string; confirmation_jwk?: ConfirmationJwk | null } = {},
): Promise<Record<string, string>> {
  const lowered = lowercase_header_map(headers);
  if (lowered["authorization"] === undefined) {
    throw new Error("sign_request needs the Authorization header it protects");
  }
  const added: Record<string, string> = {};
  const covered: Array<[string, string]> = [
    ["@method", method.toUpperCase()],
    ["@target-uri", target_uri],
    ["authorization", lowered["authorization"].trim()],
  ];
  if (body && body.length > 0) {
    added["Content-Digest"] = compute_content_digest_header_value_for_request_body(body);
    covered.push(["content-digest", added["Content-Digest"]]);
  }
  if (lowered["content-type"] !== undefined) {
    covered.push(["content-type", lowered["content-type"].trim()]);
  }
  const created = options.created ?? Math.floor(Date.now() / 1000);
  const nonce = options.nonce ?? crypto.randomBytes(16).toString("base64url");
  const keyid = options.confirmation_jwk ? compute_rfc7638_jwk_sha256_thumbprint(options.confirmation_jwk) : null;
  const parameters = serialize_airs_signature_parameters(covered.map(([name]) => name), created, nonce, keyid);
  const signature = await sign_signature_base_with_confirmation_key(build_airs_signature_base(covered, parameters));
  added["Signature-Input"] = `${AIRS_SIGNATURE_LABEL}=${parameters}`;
  added["Signature"] = `${AIRS_SIGNATURE_LABEL}=:${signature.toString("base64")}:`;
  return added;
}

/** The minimal Token surface needed to sign (see identity.ts Token). */
export interface SenderConstrainedTokenLike {
  readonly access_token: string;
  readonly token_type: string;
  readonly airs_request_signer?: AirsRequestSigner;
  readonly confirmation_jwk?: ConfirmationJwk | null;
  readonly server_clock_offset_seconds?: number;
}

/** Issuer clock minus local clock, from the token's iat at arrival (read unverified; it only steers `created`). */
export function server_clock_offset_seconds_from_access_token(access_token: string, received_at_epoch_seconds = Date.now() / 1000): number {
  try {
    const issued_at = JSON.parse(Buffer.from(access_token.split(".")[1], "base64url").toString("utf8")).iat;
    return typeof issued_at === "number" ? issued_at - received_at_epoch_seconds : 0;
  } catch {
    return 0;
  }
}

/** Headers for a sender-constrained request: Authorization + the AIRS signature over exactly this request. */
export async function build_sender_constrained_request_headers(
  token: SenderConstrainedTokenLike, method: string, url: string, body: Buffer | null,
  other_headers: Record<string, string> = {},
): Promise<Record<string, string>> {
  if (!token.airs_request_signer) {
    throw new Error(
      "this Token cannot sign requests (it was not issued through getToken()); AIRS tokens are " +
      "sender-constrained and are never sent as bare bearer tokens");
  }
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(other_headers)) {
    if (name.toLowerCase() !== "authorization") { headers[name] = value; }
  }
  headers["Authorization"] = `${token.token_type} ${token.access_token}`;
  const signature_headers = await sign_request(
    method, new URL(url).href, headers, body, token.airs_request_signer,
    {
      confirmation_jwk: token.confirmation_jwk ?? null,
      // `created` on the issuer's clock, so a drifting agent clock is not refused
      created: Math.floor(Date.now() / 1000 + (token.server_clock_offset_seconds ?? 0)),
    });
  return { ...headers, ...signature_headers };
}

function header_init_to_record(headers: RequestInit["headers"]): Record<string, string> {
  const record: Record<string, string> = {};
  if (!headers) { return record; }
  if (typeof (headers as Headers).forEach === "function" && !Array.isArray(headers)) {
    (headers as Headers).forEach((value, name) => { record[name] = value; });
  } else if (Array.isArray(headers)) {
    for (const [name, value] of headers) { record[name] = value; }
  } else {
    Object.assign(record, headers as Record<string, string>);
  }
  return record;
}

/** fetch() that sends the token sender-constrained: Authorization + an AIRS signature over the exact method, URL and body. */
export async function fetch_with_airs_proof_of_possession(
  token: SenderConstrainedTokenLike, url: string, init: RequestInit = {},
): Promise<Response> {
  let body: Buffer | null = null;
  if (typeof init.body === "string") {
    body = Buffer.from(init.body, "utf8");
  } else if (init.body instanceof Uint8Array) {
    body = Buffer.from(init.body);
  } else if (init.body != null) {
    throw new Error("fetch_with_airs_proof_of_possession signs string or byte bodies only");
  }
  const method = (init.method ?? "GET").toUpperCase();
  const headers = await build_sender_constrained_request_headers(
    token, method, url, body, header_init_to_record(init.headers));
  return fetch(url, { ...init, method, headers, body: body ?? undefined });
}

// ---------------------------------------------------------------------------
// Verification (relying parties)
// ---------------------------------------------------------------------------

function split_top_level_dictionary_members(field_value: string): string[] {
  const members: string[] = [];
  let depth = 0;
  let in_string = false;
  let current = "";
  for (let index = 0; index < field_value.length; index++) {
    const character = field_value[index];
    if (in_string) {
      current += character;
      if (character === "\\" && index + 1 < field_value.length) { current += field_value[++index]; }
      else if (character === "\"") { in_string = false; }
    } else if (character === "\"") { in_string = true; current += character; }
    else if (character === "(") { depth++; current += character; }
    else if (character === ")") { depth--; current += character; }
    else if (character === "," && depth === 0) { members.push(current.trim()); current = ""; }
    else { current += character; }
  }
  if (current.trim()) { members.push(current.trim()); }
  return members;
}

function dictionary_members_by_label(field_value: string): Record<string, string> {
  const members: Record<string, string> = {};
  for (const member of split_top_level_dictionary_members(field_value)) {
    const separator = member.indexOf("=");
    const label = separator < 0 ? "" : member.slice(0, separator).trim();
    if (!/^[a-z*][a-z0-9_\-.*]*$/.test(label)) {
      throw new AirsHttpMessageSignatureRejected("malformed signature dictionary member");
    }
    members[label] = member.slice(separator + 1).trim();
  }
  return members;
}

function parse_signature_input_member(member_value: string): { components: string[]; parameters: Record<string, string | number> } {
  const match = /^\(\s*((?:"[^"\\]*"\s*)*)\)(.*)$/s.exec(member_value.trim());
  if (!match) { throw new AirsHttpMessageSignatureRejected("Signature-Input member is not an inner list"); }
  const components = Array.from(match[1].matchAll(/"([^"\\]*)"/g), (m) => m[1]);
  const parameters: Record<string, string | number> = {};
  for (const parameter of match[2].matchAll(/;\s*([a-z*][a-z0-9_\-.*]*)(?:=("(?:[^"\\]|\\.)*"|-?\d+|[A-Za-z*][A-Za-z0-9:/%*._!#$&'+^`|~-]*))?/g)) {
    const raw = parameter[2];
    if (raw === undefined) { parameters[parameter[1]] = ""; continue; }
    parameters[parameter[1]] = raw.startsWith("\"") ? raw.slice(1, -1).replace(/\\"/g, "\"").replace(/\\\\/g, "\\")
      : /^-?\d+$/.test(raw) ? Number(raw) : raw;
  }
  return { components, parameters };
}

function verify_signature_with_confirmation_jwk(jwk: ConfirmationJwk, signature: Buffer, signature_base: Buffer): void {
  let public_key: crypto.KeyObject;
  try {
    public_key = crypto.createPublicKey(
      { key: jwk, format: "jwk" } as unknown as Parameters<typeof crypto.createPublicKey>[0]);
  } catch {
    throw new AirsHttpMessageSignatureRejected("cnf.jwk is not a usable public key");
  }
  let valid: boolean;
  if (jwk.kty === "RSA") {
    valid = crypto.verify("sha256", signature_base, { key: public_key, padding: crypto.constants.RSA_PKCS1_PADDING }, signature);
  } else if (jwk.kty === "EC" && jwk.crv === "P-256") {
    if (signature.length !== 64) { throw new AirsHttpMessageSignatureRejected("ecdsa-p256-sha256 signature must be 64 octets (r||s)"); }
    valid = crypto.verify("sha256", signature_base, { key: public_key, dsaEncoding: "ieee-p1363" }, signature);
  } else if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
    valid = crypto.verify(null, signature_base, public_key, signature);
  } else {
    throw new AirsHttpMessageSignatureRejected(`cnf.jwk key type ${jwk.kty} is not an AIRS confirmation key`);
  }
  if (!valid) { throw new AirsHttpMessageSignatureRejected("signature does not verify with the token's cnf.jwk"); }
}

/**
 * Verify a request's AIRS proof of possession against the token's cnf.jwk.
 * target_uri is the absolute URI the client addressed. record_nonce_and_report_if_already_seen
 * must atomically record the nonce and return true for a replay.
 */
export async function verify_request(
  method: string,
  target_uri: string,
  headers: Record<string, string>,
  body: Buffer,
  confirmation_jwk: ConfirmationJwk,
  record_nonce_and_report_if_already_seen: (nonce: string, expires_at_epoch: number) => boolean | Promise<boolean>,
  now_epoch_seconds: number = Date.now() / 1000,
): Promise<void> {
  const lowered = lowercase_header_map(headers);
  if (lowered["signature-input"] === undefined || lowered["signature"] === undefined) {
    throw new AirsHttpMessageSignatureRejected(
      "missing Signature-Input/Signature: AIRS tokens are sender-constrained (registry-04), a bearer presentation is not accepted");
  }
  const signature_inputs = dictionary_members_by_label(lowered["signature-input"]);
  const signatures = dictionary_members_by_label(lowered["signature"]);
  if (!(AIRS_SIGNATURE_LABEL in signature_inputs) || !(AIRS_SIGNATURE_LABEL in signatures)) {
    throw new AirsHttpMessageSignatureRejected(`no signature labelled "${AIRS_SIGNATURE_LABEL}"`);
  }
  const { components, parameters } = parse_signature_input_member(signature_inputs[AIRS_SIGNATURE_LABEL]);
  if (parameters.tag !== AIRS_SIGNATURE_TAG) { throw new AirsHttpMessageSignatureRejected(`tag parameter must be "${AIRS_SIGNATURE_TAG}"`); }
  if ("keyid" in parameters && parameters.keyid !== compute_rfc7638_jwk_sha256_thumbprint(confirmation_jwk)) {
    throw new AirsHttpMessageSignatureRejected("keyid does not name the token's cnf.jwk");
  }
  const created = parameters.created;
  const nonce = parameters.nonce;
  if (typeof created !== "number") { throw new AirsHttpMessageSignatureRejected("created parameter missing"); }
  if (typeof nonce !== "string" || !nonce) { throw new AirsHttpMessageSignatureRejected("nonce parameter missing"); }
  if (nonce.length * 6 < MINIMUM_NONCE_BITS) { throw new AirsHttpMessageSignatureRejected(`nonce shorter than ${MINIMUM_NONCE_BITS} bits`); }
  if (created > now_epoch_seconds + ALLOWED_CLOCK_SKEW_SECONDS) { throw new AirsHttpMessageSignatureRejected("created is in the future"); }
  if (now_epoch_seconds - created > MAXIMUM_SIGNATURE_AGE_SECONDS + ALLOWED_CLOCK_SKEW_SECONDS) {
    throw new AirsHttpMessageSignatureRejected(`signature is older than ${MAXIMUM_SIGNATURE_AGE_SECONDS} s`);
  }
  for (const required of REQUIRED_COVERED_COMPONENTS) {
    if (!components.includes(required)) { throw new AirsHttpMessageSignatureRejected(`signature does not cover ${required}`); }
  }
  if (body.length > 0 && !components.includes("content-digest")) {
    throw new AirsHttpMessageSignatureRejected("request has content but the signature does not cover content-digest");
  }
  if (lowered["content-type"] !== undefined && !components.includes("content-type")) {
    throw new AirsHttpMessageSignatureRejected("Content-Type present but not covered");
  }
  if (new Set(components).size !== components.length) { throw new AirsHttpMessageSignatureRejected("a component is covered twice"); }
  const covered: Array<[string, string]> = components.map((name) => {
    if (name === "@method") { return [name, method.toUpperCase()]; }
    if (name === "@target-uri") { return [name, target_uri]; }
    if (name.startsWith("@")) { throw new AirsHttpMessageSignatureRejected(`derived component ${name} is not part of the AIRS profile`); }
    if (lowered[name] === undefined) { throw new AirsHttpMessageSignatureRejected(`covered field ${name} is absent`); }
    return [name, lowered[name].trim()];
  });
  if (components.includes("content-digest") && !content_digest_matches_body(lowered["content-digest"], body)) {
    throw new AirsHttpMessageSignatureRejected("Content-Digest does not match the received content");
  }
  const signature_value = signatures[AIRS_SIGNATURE_LABEL];
  if (signature_value.length < 2 || signature_value[0] !== ":" || signature_value[signature_value.length - 1] !== ":") {
    throw new AirsHttpMessageSignatureRejected("Signature member is not a byte sequence");
  }
  verify_signature_with_confirmation_jwk(
    confirmation_jwk, Buffer.from(signature_value.slice(1, -1), "base64"),
    build_airs_signature_base(covered, signature_inputs[AIRS_SIGNATURE_LABEL]));
  // replay check last, so an invalid signature cannot burn a victim's nonce
  if (await record_nonce_and_report_if_already_seen(
    nonce, Math.floor(created + MAXIMUM_SIGNATURE_AGE_SECONDS + ALLOWED_CLOCK_SKEW_SECONDS))) {
    throw new AirsHttpMessageSignatureRejected("nonce already used (replay)");
  }
}
