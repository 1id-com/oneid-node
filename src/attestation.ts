/**
 * Protocol-agnostic attestation primitive for the 1id.com Node.js SDK.
 *
 * Two modes of operation:
 *
 * 1. **Email attestation (RFC-compliant)**:
 *    ```ts
 *    const proof = await prepareAttestation({
 *      emailHeaders: { From: "agent@mailpal.com", To: "bob@example.com",
 *                      Subject: "Hello", Date: "...", "Message-ID": "<abc@mailpal.com>" },
 *      body: Buffer.from("Message body"),
 *    });
 *    ```
 *    The nonce is computed per draft-drake-email-hardware-attestation-00
 *    Section 5.3 using DKIM relaxed header canonicalization and a
 *    header+body+timestamp binding.
 *
 * 2. **Simple content attestation**:
 *    ```ts
 *    const proof = await prepareAttestation({ content: Buffer.from("raw bytes") });
 *    ```
 *    The nonce is base64url(SHA-256(content)). Suitable for non-email protocols.
 *
 * RFC: draft-drake-email-hardware-attestation-00 Section 5.
 * Nonce algorithm: Section 5.3 (message-binding via issuer-signed nonce).
 */

import { createHash } from "crypto";
import { get_token } from "./auth.js";
import { load_credentials } from "./credentials.js";
import { AuthenticationError, NetworkError, NotEnrolledError } from "./exceptions.js";

const _HTTP_TIMEOUT_MILLISECONDS = 15_000;

const _MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING = [
  "from", "to", "subject", "date", "message-id",
];

export interface AttestationProof {
  sd_jwt: string | null;
  sd_jwt_disclosures: Record<string, string>;
  contact_token: string | null;
  contact_address: string | null;
  tpm_signature_b64: string | null;
  content_digest: string | null;
}

export interface PrepareAttestationOptions {
  content?: Buffer;
  contentDigest?: string;
  emailHeaders?: Record<string, string>;
  body?: Buffer;
  disclosedClaims?: string[];
  includeContactToken?: boolean;
  includeSdJwt?: boolean;
  apiBaseUrl?: string;
}

export function canonicalise_header_value_using_dkim_relaxed(raw_value: string): string {
  let normalized = raw_value.replace(/\r\n/g, "\n").replace(/\n/g, "\r\n");
  let unfolded = normalized.replace(/\r\n[ \t]/g, " ");
  const compressed = unfolded.replace(/[ \t]+/g, " ");
  return compressed.trim();
}

export function canonicalise_header_name_using_dkim_relaxed(raw_name: string): string {
  return raw_name.trim().toLowerCase();
}

export function _select_headers_bottom_up_per_dkim(
  header_names_from_h_tag: string[],
  message_headers: Array<[string, string]>,
): Array<[string, string] | null> {
  const consumed_indices = new Set<number>();
  const selected: Array<[string, string] | null> = [];
  for (const requested_name of header_names_from_h_tag) {
    const target = requested_name.trim().toLowerCase();
    let found_index = -1;
    for (let i = message_headers.length - 1; i >= 0; i--) {
      if (consumed_indices.has(i)) { continue; }
      if (message_headers[i][0].trim().toLowerCase() === target) {
        found_index = i;
        break;
      }
    }
    if (found_index >= 0) {
      consumed_indices.add(found_index);
      selected.push(message_headers[found_index]);
    } else {
      selected.push(null);
    }
  }
  return selected;
}

export function canonicalise_headers_for_message_binding(
  email_headers: Record<string, string>,
  hardware_trust_proof_header_value_placeholder: string = "",
): Buffer {
  const lowered_headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(email_headers)) {
    lowered_headers[k.trim().toLowerCase()] = v;
  }

  for (const required_header_name of _MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING) {
    if (!(required_header_name in lowered_headers)) {
      throw new Error(
        `Missing required email header '${required_header_name}' for RFC message-binding nonce. ` +
        `Required headers: ${_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING.join(", ")}`
      );
    }
  }

  const header_names_for_nonce: string[] = [..._MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING];
  header_names_for_nonce.push(..._MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING);

  const message_header_pairs: Array<[string, string]> = Object.entries(lowered_headers);
  const selected = _select_headers_bottom_up_per_dkim(header_names_for_nonce, message_header_pairs);

  const canonicalised_header_lines: string[] = [];
  for (const entry of selected) {
    if (entry === null) { continue; }
    const canon_name = canonicalise_header_name_using_dkim_relaxed(entry[0]);
    const canon_value = canonicalise_header_value_using_dkim_relaxed(entry[1]);
    canonicalised_header_lines.push(`${canon_name}:${canon_value}\r\n`);
  }

  canonicalised_header_lines.push(
    `hardware-trust-proof:${hardware_trust_proof_header_value_placeholder}`
  );

  return Buffer.from(canonicalised_header_lines.join(""), "utf-8");
}

export function canonicalise_body_using_dkim_simple(body_bytes: Buffer): Buffer {
  if (body_bytes.length === 0) { return Buffer.from("\r\n"); }
  let body_string = body_bytes.toString("binary");
  body_string = body_string.replace(/\r\n/g, "\n").replace(/\r/g, "\n").replace(/\n/g, "\r\n");
  let result = Buffer.from(body_string, "binary");
  while (result.length >= 4 && result.subarray(-4).equals(Buffer.from("\r\n\r\n"))) {
    result = result.subarray(0, -2);
  }
  if (!result.subarray(-2).equals(Buffer.from("\r\n"))) {
    result = Buffer.concat([result, Buffer.from("\r\n")]);
  }
  return result;
}

export function compute_rfc_message_binding_nonce(
  email_headers: Record<string, string>,
  body_bytes: Buffer,
  proposed_iat_unix_timestamp: number,
): string {
  const canonicalised_header_bytes = canonicalise_headers_for_message_binding(email_headers);
  const h_hash = createHash("sha256").update(canonicalised_header_bytes).digest();

  const canonicalised_body = canonicalise_body_using_dkim_simple(body_bytes);
  const bh_raw = createHash("sha256").update(canonicalised_body).digest();

  const ts_bytes = Buffer.alloc(8);
  ts_bytes.writeBigUInt64BE(BigInt(proposed_iat_unix_timestamp));

  const message_binding = Buffer.concat([h_hash, bh_raw, ts_bytes]);
  const nonce_raw = createHash("sha256").update(message_binding).digest();

  return nonce_raw.toString("base64url");
}

const _TRUST_TIER_TO_RFC_TYP_PARAMETER: Record<string, string> = {
  "sovereign": "TPM",
  "portable": "PIV",
  "enclave": "ENC",
  "virtual": "VRT",
  "declared": "SFT",
};

export interface DirectAttestationProof {
  hardware_attestation_header_value: string;
  content_digest: string;
}

export function canonicalise_headers_for_direct_attestation(
  email_headers: Record<string, string>,
  hardware_attestation_header_value_without_chain: string = "",
): Buffer {
  const lowered_headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(email_headers)) {
    lowered_headers[k.trim().toLowerCase()] = v;
  }

  for (const required_header_name of _MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING) {
    if (!(required_header_name in lowered_headers)) {
      throw new Error(
        `Missing required email header '${required_header_name}' for Mode 1 attestation. ` +
        `Required headers: ${_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING.join(", ")}`
      );
    }
  }

  const all_header_names: string[] = [..._MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING];
  const extra_names = Object.keys(lowered_headers).filter(
    h => !_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING.includes(h) &&
         h !== "hardware-attestation" && h !== "hardware-trust-proof"
  ).sort();
  all_header_names.push(...extra_names);
  all_header_names.push(...all_header_names);

  const message_header_pairs: Array<[string, string]> = Object.entries(lowered_headers);
  const selected = _select_headers_bottom_up_per_dkim(all_header_names, message_header_pairs);

  const canonicalised_header_lines: string[] = [];
  for (const entry of selected) {
    if (entry === null) { continue; }
    const canon_name = canonicalise_header_name_using_dkim_relaxed(entry[0]);
    const canon_value = canonicalise_header_value_using_dkim_relaxed(entry[1]);
    canonicalised_header_lines.push(`${canon_name}:${canon_value}\r\n`);
  }

  canonicalised_header_lines.push(
    `hardware-attestation:${hardware_attestation_header_value_without_chain}`
  );

  return Buffer.from(canonicalised_header_lines.join(""), "utf-8");
}

export function compute_attestation_digest_for_direct_mode(
  email_headers: Record<string, string>,
  body_bytes: Buffer,
  attestation_timestamp_unix: number,
  hardware_attestation_header_value_without_chain: string = "",
): Buffer {
  const canonicalised_header_bytes = canonicalise_headers_for_direct_attestation(
    email_headers, hardware_attestation_header_value_without_chain,
  );
  const h_hash = createHash("sha256").update(canonicalised_header_bytes).digest();

  const canonicalised_body = canonicalise_body_using_dkim_simple(body_bytes);
  const bh_raw = createHash("sha256").update(canonicalised_body).digest();

  const ts_bytes = Buffer.alloc(8);
  ts_bytes.writeBigUInt64BE(BigInt(attestation_timestamp_unix));

  const attestation_input = Buffer.concat([h_hash, bh_raw, ts_bytes]);
  return createHash("sha256").update(attestation_input).digest();
}

function der_encode_length(length_value: number): Buffer {
  if (length_value < 0x80) { return Buffer.from([length_value]); }
  if (length_value < 0x100) { return Buffer.from([0x81, length_value]); }
  if (length_value < 0x10000) { return Buffer.from([0x82, (length_value >> 8) & 0xFF, length_value & 0xFF]); }
  return Buffer.from([0x83, (length_value >> 16) & 0xFF, (length_value >> 8) & 0xFF, length_value & 0xFF]);
}

function der_encode_tlv(tag_byte: number, content_bytes: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag_byte]), der_encode_length(content_bytes.length), content_bytes]);
}

function der_encode_integer(integer_value: bigint): Buffer {
  if (integer_value === 0n) { return der_encode_tlv(0x02, Buffer.from([0x00])); }
  const hex = integer_value.toString(16);
  const padded_hex = hex.length % 2 ? "0" + hex : hex;
  let byte_buffer = Buffer.from(padded_hex, "hex");
  if (byte_buffer[0]! >= 0x80) {
    byte_buffer = Buffer.concat([Buffer.from([0x00]), byte_buffer]);
  }
  return der_encode_tlv(0x02, byte_buffer);
}

function der_encode_oid(oid_dotted_string: string): Buffer {
  const components = oid_dotted_string.split(".").map(Number);
  const encoded_body: number[] = [40 * components[0]! + components[1]!];
  for (let i = 2; i < components.length; i++) {
    const component = components[i]!;
    if (component < 0x80) {
      encoded_body.push(component);
    } else {
      const base128_digits: number[] = [];
      let remaining = component;
      while (remaining > 0) {
        base128_digits.push(remaining & 0x7F);
        remaining >>= 7;
      }
      base128_digits.reverse();
      for (let j = 0; j < base128_digits.length; j++) {
        encoded_body.push(j < base128_digits.length - 1 ? base128_digits[j]! | 0x80 : base128_digits[j]!);
      }
    }
  }
  return der_encode_tlv(0x06, Buffer.from(encoded_body));
}

const _OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const _OID_DATA = "1.2.840.113549.1.7.1";
const _OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const _OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
const _OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";

const _RFC_ALG_TO_SIGNATURE_OID: Record<string, string> = {
  "RS256": _OID_SHA256_WITH_RSA,
  "ES256": _OID_ECDSA_WITH_SHA256,
};

function parse_pem_certificates_to_der(certificate_chain_pem: string): Buffer[] {
  const certificate_der_list: Buffer[] = [];
  for (const pem_block of certificate_chain_pem.split("-----END CERTIFICATE-----")) {
    const trimmed = pem_block.trim();
    if (trimmed && trimmed.includes("-----BEGIN CERTIFICATE-----")) {
      const b64 = trimmed.replace("-----BEGIN CERTIFICATE-----", "").replace(/\s/g, "");
      certificate_der_list.push(Buffer.from(b64, "base64"));
    }
  }
  return certificate_der_list;
}

function extract_issuer_and_serial_from_der(cert_der: Buffer): { issuer_der: Buffer; serial_number: bigint } {
  let pos = 0;
  const read_tag_length = (offset: number): { tag: number; length: number; value_offset: number } => {
    const tag = cert_der[offset]!;
    offset++;
    let length = cert_der[offset]!;
    offset++;
    if (length > 127) {
      const num_bytes = length & 0x7F;
      length = 0;
      for (let i = 0; i < num_bytes; i++) {
        length = (length << 8) | cert_der[offset]!;
        offset++;
      }
    }
    return { tag, length, value_offset: offset };
  };

  const outer = read_tag_length(pos);
  const tbs = read_tag_length(outer.value_offset);
  let tbs_pos = tbs.value_offset;

  const first_elem = read_tag_length(tbs_pos);
  if (first_elem.tag === 0xA0) {
    tbs_pos = first_elem.value_offset + first_elem.length;
  }

  const serial = read_tag_length(tbs_pos);
  const serial_bytes = cert_der.subarray(serial.value_offset, serial.value_offset + serial.length);
  let serial_number = 0n;
  for (const byte_value of serial_bytes) {
    serial_number = (serial_number << 8n) | BigInt(byte_value);
  }
  tbs_pos = serial.value_offset + serial.length;

  const sig_alg = read_tag_length(tbs_pos);
  tbs_pos = sig_alg.value_offset + sig_alg.length;

  const issuer = read_tag_length(tbs_pos);
  const issuer_der = cert_der.subarray(tbs_pos, issuer.value_offset + issuer.length);

  return { issuer_der, serial_number };
}

export function build_cms_signed_data_for_direct_attestation(
  signature_bytes: Buffer,
  certificate_chain_pem: string,
  signature_algorithm_rfc_name: string,
): Buffer {
  const certificate_der_list = parse_pem_certificates_to_der(certificate_chain_pem);
  if (certificate_der_list.length === 0) {
    throw new Error("Certificate chain PEM contains no parseable certificates");
  }

  const signature_oid_string = _RFC_ALG_TO_SIGNATURE_OID[signature_algorithm_rfc_name];
  if (!signature_oid_string) {
    throw new Error(`Unsupported signature algorithm: ${signature_algorithm_rfc_name}`);
  }

  const sha256_algorithm_identifier = der_encode_tlv(0x30,
    Buffer.concat([der_encode_oid(_OID_SHA256), der_encode_tlv(0x05, Buffer.alloc(0))]));

  const digest_algorithms_set = der_encode_tlv(0x31, sha256_algorithm_identifier);
  const encap_content_info = der_encode_tlv(0x30, der_encode_oid(_OID_DATA));
  const all_certs_content = Buffer.concat(certificate_der_list);
  const certificates_implicit_set = der_encode_tlv(0xA0, all_certs_content);

  const { issuer_der, serial_number } = extract_issuer_and_serial_from_der(certificate_der_list[0]!);
  const issuer_and_serial_number = der_encode_tlv(0x30,
    Buffer.concat([issuer_der, der_encode_integer(serial_number)]));

  const signature_algorithm_identifier = der_encode_tlv(0x30, der_encode_oid(signature_oid_string));
  const signature_octet_string = der_encode_tlv(0x04, signature_bytes);

  const signer_info = der_encode_tlv(0x30, Buffer.concat([
    der_encode_integer(1n),
    issuer_and_serial_number,
    sha256_algorithm_identifier,
    signature_algorithm_identifier,
    signature_octet_string,
  ]));

  const signer_infos_set = der_encode_tlv(0x31, signer_info);

  const signed_data = der_encode_tlv(0x30, Buffer.concat([
    der_encode_integer(1n),
    digest_algorithms_set,
    encap_content_info,
    certificates_implicit_set,
    signer_infos_set,
  ]));

  return der_encode_tlv(0x30, Buffer.concat([
    der_encode_oid(_OID_SIGNED_DATA),
    der_encode_tlv(0xA0, signed_data),
  ]));
}

export async function prepare_direct_hardware_attestation(
  email_headers: Record<string, string>,
  body: Buffer,
  agent_identity_urn?: string,
): Promise<DirectAttestationProof> {
  const creds = load_credentials();
  const trust_tier = creds.trust_tier ?? "declared";
  const typ_parameter = _TRUST_TIER_TO_RFC_TYP_PARAMETER[trust_tier] ?? "SFT";

  if (!creds.identity_certificate_chain_pem) {
    throw new NotEnrolledError(
      "Mode 1 (Direct Hardware Attestation) requires a certificate chain. " +
      "Re-enroll to obtain an identity certificate."
    );
  }

  if (!agent_identity_urn) {
    agent_identity_urn = creds.agent_identity_urn ?? undefined;
  }

  const attestation_timestamp = Math.floor(Date.now() / 1000);

  const canonicalised_body = canonicalise_body_using_dkim_simple(body);
  const bh_raw = createHash("sha256").update(canonicalised_body).digest();
  const bh_base64url = bh_raw.toString("base64url");

  const lowered_headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(email_headers)) {
    lowered_headers[k.trim().toLowerCase()] = v;
  }
  const all_signed_names: string[] = [..._MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING];
  const extra_header_names = Object.keys(lowered_headers).filter(
    h => !_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING.includes(h) &&
         h !== "hardware-attestation" && h !== "hardware-trust-proof"
  ).sort();
  all_signed_names.push(...extra_header_names);
  const signed_header_names = all_signed_names.join(":") + ":" + all_signed_names.join(":");

  let algorithm_for_header: string;
  if (trust_tier === "sovereign" || trust_tier === "virtual" || creds.key_algorithm === "tpm-ak") {
    algorithm_for_header = "RS256";
  } else if (trust_tier === "portable" || trust_tier === "enclave" || creds.hsm_key_reference === "piv-slot-9a") {
    algorithm_for_header = "ES256";
  } else if (creds.private_key_pem) {
    const { determine_signing_algorithm_name } = await import("./verify.js");
    algorithm_for_header = determine_signing_algorithm_name(creds);
  } else {
    throw new NotEnrolledError("No signing key available for Mode 1 attestation.");
  }

  let header_template_without_chain = (
    `v=1; typ=${typ_parameter}; alg=${algorithm_for_header}; ` +
    `h=${signed_header_names}; bh=${bh_base64url}; ts=${attestation_timestamp}; ` +
    `chain=`
  );
  if (agent_identity_urn) {
    header_template_without_chain += `; aid=${agent_identity_urn}`;
  }

  const attestation_digest = compute_attestation_digest_for_direct_mode(
    email_headers, body, attestation_timestamp, header_template_without_chain,
  );

  let signature_bytes: Buffer;
  if (trust_tier === "sovereign" || trust_tier === "virtual" || creds.key_algorithm === "tpm-ak") {
    const { sign_challenge_with_tpm } = await import("./helper.js");
    const result = await sign_challenge_with_tpm(attestation_digest.toString("base64"), creds.hsm_key_reference ?? "");
    signature_bytes = Buffer.from((result["signature_b64"] as string) ?? "", "base64");
  } else if (trust_tier === "portable" || creds.hsm_key_reference === "piv-slot-9a") {
    const { sign_challenge_with_piv } = await import("./helper.js");
    const result = await sign_challenge_with_piv(attestation_digest.toString("base64"));
    signature_bytes = Buffer.from((result["signature_b64"] as string) ?? "", "base64");
  } else if (trust_tier === "enclave") {
    const { sign_challenge_with_enclave } = await import("./helper.js");
    const result = await sign_challenge_with_enclave(attestation_digest.toString("base64"));
    signature_bytes = Buffer.from((result["signature_b64"] as string) ?? "", "base64");
  } else if (creds.private_key_pem) {
    const { sign_challenge_with_private_key } = await import("./keys.js");
    signature_bytes = sign_challenge_with_private_key(creds.private_key_pem, attestation_digest);
  } else {
    throw new NotEnrolledError("No signing key available.");
  }

  const cms_der_bytes = build_cms_signed_data_for_direct_attestation(
    signature_bytes, creds.identity_certificate_chain_pem, algorithm_for_header,
  );
  const chain_base64 = cms_der_bytes.toString("base64");

  let final_header_value = (
    `v=1; typ=${typ_parameter}; alg=${algorithm_for_header}; ` +
    `h=${signed_header_names}; bh=${bh_base64url}; ts=${attestation_timestamp}; ` +
    `chain=${chain_base64}`
  );
  if (agent_identity_urn) {
    final_header_value += `; aid=${agent_identity_urn}`;
  }

  const body_digest_hex = createHash("sha256").update(body).digest("hex");

  return {
    hardware_attestation_header_value: final_header_value,
    content_digest: `sha256:${body_digest_hex}`,
  };
}

export async function prepareAttestation(
  options: PrepareAttestationOptions = {},
): Promise<AttestationProof> {
  const {
    content,
    contentDigest,
    emailHeaders,
    body,
    disclosedClaims = ["trust_tier"],
    includeContactToken = true,
    includeSdJwt = true,
    apiBaseUrl,
  } = options;

  const rfc_email_mode_is_active = emailHeaders != null;
  const simple_content_mode_is_active = content != null || contentDigest != null;

  if (rfc_email_mode_is_active && simple_content_mode_is_active) {
    throw new Error(
      "Cannot mix emailHeaders/body with content/contentDigest. " +
      "Use emailHeaders+body for RFC email attestation, OR content/contentDigest for simple mode."
    );
  }

  if (rfc_email_mode_is_active && body == null) {
    throw new Error("body is required when emailHeaders is provided.");
  }

  if (content != null && contentDigest != null) {
    throw new Error("Provide content OR contentDigest, not both.");
  }

  if (!rfc_email_mode_is_active && !simple_content_mode_is_active && includeSdJwt) {
    throw new Error(
      "SD-JWT attestation requires content to bind to. " +
      "Provide emailHeaders + body (RFC email mode), OR content/contentDigest (simple mode)."
    );
  }

  let effective_content_digest: string | null = null;
  if (content != null) {
    const digest_hex = createHash("sha256").update(content).digest("hex");
    effective_content_digest = `sha256:${digest_hex}`;
  } else if (contentDigest != null) {
    effective_content_digest = contentDigest;
  } else if (rfc_email_mode_is_active && body != null) {
    const body_digest_hex = createHash("sha256").update(body).digest("hex");
    effective_content_digest = `sha256:${body_digest_hex}`;
  }

  const creds = load_credentials();
  const effective_api_base_url = apiBaseUrl ?? creds.api_base_url ?? "https://1id.com";

  const token = await get_token();
  const auth_headers: Record<string, string> = {
    "Authorization": `Bearer ${token.access_token}`,
    "Content-Type": "application/json",
  };

  const proof: AttestationProof = {
    sd_jwt: null,
    sd_jwt_disclosures: {},
    contact_token: null,
    contact_address: null,
    tpm_signature_b64: null,
    content_digest: effective_content_digest,
  };

  if (includeSdJwt) {
    const proposed_iat = Math.floor(Date.now() / 1000);
    let nonce_value: string;

    if (rfc_email_mode_is_active && body != null) {
      nonce_value = compute_rfc_message_binding_nonce(
        emailHeaders!,
        body,
        proposed_iat,
      );
    } else {
      const message_hash = effective_content_digest?.includes(":")
        ? effective_content_digest.split(":")[1]
        : (effective_content_digest ?? "");
      nonce_value = Buffer.from(message_hash, "hex").toString("base64url");
    }

    const sd_jwt_result = await _fetch_sd_jwt_proof_for_message(
      effective_api_base_url,
      auth_headers,
      nonce_value,
      proposed_iat,
      disclosedClaims,
    );
    proof.sd_jwt = sd_jwt_result.sd_jwt;
    proof.sd_jwt_disclosures = sd_jwt_result.disclosures;
  }

  if (includeContactToken) {
    const contact_result = await _fetch_contact_token(effective_api_base_url, auth_headers);
    proof.contact_token = contact_result.token;
    proof.contact_address = contact_result.contact_address;
  }

  return proof;
}

async function _fetch_sd_jwt_proof_for_message(
  api_base_url: string,
  auth_headers: Record<string, string>,
  precomputed_nonce: string,
  proposed_iat: number,
  disclosed_claims: string[],
): Promise<{ sd_jwt: string | null; disclosures: Record<string, string> }> {
  const url = `${api_base_url}/api/v1/proof/sd-jwt/message`;

  const response = await fetch(url, {
    method: "POST",
    headers: auth_headers,
    body: JSON.stringify({
      nonce: precomputed_nonce,
      proposed_iat,
      disclosed_claims,
    }),
    signal: AbortSignal.timeout(_HTTP_TIMEOUT_MILLISECONDS),
  });

  if (response.status === 401) {
    throw new AuthenticationError("Bearer token rejected by SD-JWT endpoint.");
  }
  if (!response.ok) {
    console.error(
      `SD-JWT request failed (HTTP ${response.status}): ${(await response.text()).slice(0, 300)} -- Hardware-Trust-Proof header will be MISSING`
    );
    return { sd_jwt: null, disclosures: {} };
  }

  let data = await response.json() as Record<string, any>;
  if ("data" in data) { data = data.data; }
  return {
    sd_jwt: data.sd_jwt ?? null,
    disclosures: data.disclosures ?? {},
  };
}

async function _fetch_contact_token(
  api_base_url: string,
  auth_headers: Record<string, string>,
): Promise<{ token: string | null; contact_address: string | null }> {
  const url = `${api_base_url}/api/v1/contact-token`;

  try {
    const response = await fetch(url, {
      method: "GET",
      headers: auth_headers,
      signal: AbortSignal.timeout(_HTTP_TIMEOUT_MILLISECONDS),
    });

    if (!response.ok) {
      console.warn(`Contact token request failed (HTTP ${response.status})`);
      return { token: null, contact_address: null };
    }

    const data = (await response.json() as Record<string, any>).data ?? {};
    return {
      token: data.token ?? null,
      contact_address: data.contact_address ?? null,
    };
  } catch {
    return { token: null, contact_address: null };
  }
}

