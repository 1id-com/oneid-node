/**
 * 1id Peer Identity Verification
 *
 * Assembles and validates proof bundles for offline, privacy-preserving
 * agent-to-agent identity verification.
 *
 * Protocol:
 *   1. Verifier generates a random nonce (32+ bytes)
 *   2. Agent calls signChallenge(nonce) -> IdentityProofBundle
 *   3. Verifier calls verifyPeerIdentity(nonce, bundle)
 *      -> VerifiedPeerIdentity
 *
 * No secrets are exchanged. The verifier never contacts 1ID. Once the
 * trust root is cached locally, verification is entirely offline.
 */

import * as crypto from "node:crypto";
import { load_credentials, type StoredCredentials } from "./credentials.js";
import { NotEnrolledError, OneIDError } from "./exceptions.js";
import { sign_challenge_with_private_key } from "./keys.js";
import { get_trust_roots, parse_pem_bundle_into_certificates } from "./trustRoots.js";

const ONEID_OID_TRUST_TIER = "1.3.6.1.4.1.59999.1.1";
const ONEID_OID_ENROLLED_AT = "1.3.6.1.4.1.59999.1.2";
const ONEID_OID_HARDWARE_LOCKED = "1.3.6.1.4.1.59999.1.3";

export class PeerVerificationError extends OneIDError {
  constructor(message: string, error_code: string = "PEER_VERIFICATION_ERROR") {
    super(message, error_code);
    this.name = "PeerVerificationError";
  }
}

export class CertificateChainValidationError extends PeerVerificationError {
  constructor(message: string) {
    super(message, "CERTIFICATE_CHAIN_VALIDATION_ERROR");
    this.name = "CertificateChainValidationError";
  }
}

export class SignatureVerificationError extends PeerVerificationError {
  constructor(message: string) {
    super(message, "SIGNATURE_VERIFICATION_ERROR");
    this.name = "SignatureVerificationError";
  }
}

export class MissingIdentityCertificateError extends PeerVerificationError {
  constructor(message: string) {
    super(message, "MISSING_IDENTITY_CERTIFICATE");
    this.name = "MissingIdentityCertificateError";
  }
}

export interface IdentityProofBundle {
  signature_b64: string;
  certificate_chain_pem: string;
  agent_id: string;
  trust_tier: string;
  algorithm: string;
}

export interface VerifiedPeerIdentity {
  agent_id: string;
  trust_tier: string;
  enrolled_at: string;
  hardware_locked: boolean;
  chain_valid: boolean;
}

function determine_signing_algorithm_name(creds: StoredCredentials): string {
  const algo = (creds.key_algorithm ?? "").toLowerCase();
  if (algo.includes("ed25519")) { return "EdDSA"; }
  if (algo.includes("p-384") || algo.includes("p384") || algo.includes("ecdsa-p384")) { return "ES384"; }
  if (algo.includes("p-256") || algo.includes("p256") || algo.includes("ecdsa") || algo.includes("piv")) { return "ES256"; }
  if (algo.includes("rsa") || algo.includes("tpm-ak")) { return "RS256"; }
  return "RS256";
}

async function sign_with_tpm(nonce_bytes: Buffer, ak_handle: string): Promise<{ signature_bytes: Buffer; algorithm: string }> {
  const { sign_challenge_with_tpm } = await import("./helper.js");
  const nonce_b64 = nonce_bytes.toString("base64");
  const result = await sign_challenge_with_tpm(nonce_b64, ak_handle);
  const signature_b64 = (result["signature_b64"] as string) ?? "";
  const algorithm_raw = (result["algorithm"] as string) ?? "RSASSA-SHA256";
  const algorithm = algorithm_raw.toUpperCase().includes("RSA") ? "RS256" : algorithm_raw;
  return { signature_bytes: Buffer.from(signature_b64, "base64"), algorithm };
}

async function sign_with_piv(nonce_bytes: Buffer): Promise<{ signature_bytes: Buffer; algorithm: string }> {
  const { sign_challenge_with_piv } = await import("./helper.js");
  const nonce_b64 = nonce_bytes.toString("base64");
  const result = await sign_challenge_with_piv(nonce_b64);
  const signature_b64 = (result["signature_b64"] as string) ?? "";
  const algorithm_raw = (result["algorithm"] as string) ?? "ECDSA-SHA256";
  const algorithm = algorithm_raw.toUpperCase().includes("ECDSA") ? "ES256" : algorithm_raw;
  return { signature_bytes: Buffer.from(signature_b64, "base64"), algorithm };
}

/**
 * Sign a verifier-provided nonce and assemble a proof bundle.
 *
 * Dispatches to the appropriate signing mechanism based on trust tier:
 *   - sovereign (TPM): delegates to oneid-enroll sign
 *   - portable (YubiKey): delegates to oneid-enroll piv-sign
 *   - declared (software): signs with local private key
 *
 * @param nonce_bytes Raw bytes of the verifier-generated nonce.
 * @returns IdentityProofBundle ready to send to the verifier.
 */
export async function signChallenge(nonce_bytes: Buffer): Promise<IdentityProofBundle> {
  const creds = load_credentials();

  if (!creds.identity_certificate_chain_pem) {
    throw new MissingIdentityCertificateError(
      "No identity certificate chain found in credentials. " +
      "This agent was enrolled before certificate issuance was available. " +
      "Re-enroll or recover your identity to obtain a certificate."
    );
  }

  const trust_tier = creds.trust_tier ?? "declared";
  const agent_id = creds.client_id;
  let signature_bytes: Buffer;
  let algorithm: string;

  if (trust_tier === "sovereign" || trust_tier === "virtual" || creds.key_algorithm === "tpm-ak") {
    const ak_handle = creds.hsm_key_reference ?? "";
    const result = await sign_with_tpm(nonce_bytes, ak_handle);
    signature_bytes = result.signature_bytes;
    algorithm = result.algorithm;
  } else if (trust_tier === "portable" || creds.hsm_key_reference === "piv-slot-9a") {
    const result = await sign_with_piv(nonce_bytes);
    signature_bytes = result.signature_bytes;
    algorithm = result.algorithm;
  } else if (creds.private_key_pem) {
    signature_bytes = sign_challenge_with_private_key(creds.private_key_pem, nonce_bytes);
    algorithm = determine_signing_algorithm_name(creds);
  } else {
    throw new NotEnrolledError(
      "Cannot sign challenge: no signing key available. " +
      "Credentials exist but contain neither a private key nor an HSM reference."
    );
  }

  return {
    signature_b64: signature_bytes.toString("base64"),
    certificate_chain_pem: creds.identity_certificate_chain_pem,
    agent_id,
    trust_tier,
    algorithm,
  };
}

/**
 * Extract the value of a custom extension by OID from a certificate.
 * Node.js X509Certificate doesn't expose arbitrary extensions directly,
 * so we parse the raw DER to find it.
 */
function extract_custom_extension_value_from_raw_der(cert: crypto.X509Certificate, target_oid: string): Buffer | null {
  const info_access = cert.infoAccess;
  // Node.js X509Certificate doesn't expose custom OIDs through its API.
  // We look for the OID in the raw DER data as a fallback.
  const raw = cert.raw;
  const oid_parts = target_oid.split(".").map(Number);

  // Encode the OID in DER format for searching
  const encoded_oid_bytes: number[] = [];
  encoded_oid_bytes.push(40 * oid_parts[0]! + oid_parts[1]!);
  for (let i = 2; i < oid_parts.length; i++) {
    let value = oid_parts[i]!;
    if (value < 128) {
      encoded_oid_bytes.push(value);
    } else {
      const temp: number[] = [];
      temp.push(value & 0x7f);
      value >>= 7;
      while (value > 0) {
        temp.push((value & 0x7f) | 0x80);
        value >>= 7;
      }
      temp.reverse();
      encoded_oid_bytes.push(...temp);
    }
  }

  const oid_buffer = Buffer.from(encoded_oid_bytes);

  // Search for the OID in the raw DER
  let search_offset = 0;
  while (search_offset < raw.length - oid_buffer.length) {
    const found_at = raw.indexOf(oid_buffer, search_offset);
    if (found_at === -1) { break; }

    // The extension value follows: OID -> critical flag -> OCTET STRING wrapping the value
    // Walk past the OID to find the OCTET STRING (tag 0x04) containing the value
    let pos = found_at + oid_buffer.length;
    // Skip past remaining TLV structures until we find the OCTET STRING
    let depth = 0;
    while (pos < raw.length && depth < 20) {
      const tag = raw[pos]!;
      if (tag === 0x04) { // OCTET STRING
        pos++;
        let octet_length = raw[pos]!;
        pos++;
        if (octet_length > 127) {
          const num_length_bytes = octet_length & 0x7f;
          octet_length = 0;
          for (let j = 0; j < num_length_bytes; j++) {
            octet_length = (octet_length << 8) | raw[pos]!;
            pos++;
          }
        }
        return raw.subarray(pos, pos + octet_length);
      }
      // Skip this TLV
      pos++;
      if (pos >= raw.length) { break; }
      let skip_length = raw[pos]!;
      pos++;
      if (skip_length > 127) {
        const num_bytes = skip_length & 0x7f;
        skip_length = 0;
        for (let j = 0; j < num_bytes; j++) {
          skip_length = (skip_length << 8) | raw[pos]!;
          pos++;
        }
      }
      pos += skip_length;
      depth++;
    }

    search_offset = found_at + 1;
  }

  return null;
}

function verify_certificate_chain_signatures(chain: crypto.X509Certificate[]): void {
  for (let i = 0; i < chain.length - 1; i++) {
    const child = chain[i]!;
    const parent = chain[i + 1]!;
    if (!child.checkIssued(parent)) {
      throw new CertificateChainValidationError(
        `Certificate at position ${i} is not issued by certificate at position ${i + 1}`
      );
    }
  }
}

function verify_chain_terminates_at_trusted_root(
  chain: crypto.X509Certificate[],
  trusted_roots: crypto.X509Certificate[],
): void {
  if (chain.length === 0) {
    throw new CertificateChainValidationError("Certificate chain is empty");
  }

  const chain_root = chain[chain.length - 1]!;
  const chain_root_fingerprint = chain_root.fingerprint256;

  const root_is_trusted = trusted_roots.some(
    (root) => root.fingerprint256 === chain_root_fingerprint
  );

  if (!root_is_trusted) {
    throw new CertificateChainValidationError(
      `Chain root '${chain_root.subject}' is not in the set of trusted 1ID roots`
    );
  }
}

function verify_nonce_signature(
  nonce_bytes: Buffer,
  signature_bytes: Buffer,
  leaf_cert: crypto.X509Certificate,
): void {
  const public_key = leaf_cert.publicKey;
  const key_type = public_key.asymmetricKeyType;

  let signature_is_valid = false;

  if (key_type === "ed25519") {
    signature_is_valid = crypto.verify(null, nonce_bytes, public_key, signature_bytes);
  } else if (key_type === "ec") {
    const curve_name = public_key.asymmetricKeyDetails?.namedCurve;
    const hash_algorithm = curve_name === "P-384" ? "sha384" : "sha256";
    signature_is_valid = crypto.verify(hash_algorithm, nonce_bytes, public_key, signature_bytes);
  } else if (key_type === "rsa") {
    signature_is_valid = crypto.verify("sha256", nonce_bytes, {
      key: public_key,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    }, signature_bytes);
  } else {
    throw new SignatureVerificationError(`Unsupported public key type: ${key_type}`);
  }

  if (!signature_is_valid) {
    throw new SignatureVerificationError(
      "Nonce signature does not match the leaf certificate's public key"
    );
  }
}

/**
 * Validate another agent's proof bundle. Entirely offline after first trust root fetch.
 *
 * Steps:
 *   1. Parse the certificate chain from the proof bundle
 *   2. Validate the chain (each cert signed by its parent)
 *   3. Verify the chain terminates at a locally cached 1ID root
 *   4. Verify the nonce signature against the leaf certificate's public key
 *   5. Extract identity claims from the leaf cert extensions
 *
 * @param nonce_bytes The original nonce bytes that the prover was asked to sign.
 * @param proof_bundle The IdentityProofBundle from the prover.
 * @param api_base_url Override for trust root server URL (only on first call if no cache).
 * @returns VerifiedPeerIdentity with verified agent_id, trust_tier, etc.
 */
export async function verifyPeerIdentity(
  nonce_bytes: Buffer,
  proof_bundle: IdentityProofBundle,
  api_base_url?: string,
): Promise<VerifiedPeerIdentity> {
  const chain = parse_pem_bundle_into_certificates(proof_bundle.certificate_chain_pem);
  if (chain.length === 0) {
    throw new CertificateChainValidationError("Proof bundle contains no parseable certificates");
  }

  const trusted_roots = await get_trust_roots(api_base_url);

  verify_certificate_chain_signatures(chain);
  verify_chain_terminates_at_trusted_root(chain, trusted_roots);

  const leaf_cert = chain[0]!;

  const now = new Date();
  const not_before = new Date(leaf_cert.validFrom);
  const not_after = new Date(leaf_cert.validTo);
  if (not_before > now) {
    throw new CertificateChainValidationError(
      `Leaf certificate is not yet valid (not_before: ${leaf_cert.validFrom})`
    );
  }
  if (not_after < now) {
    throw new CertificateChainValidationError(
      `Leaf certificate has expired (not_after: ${leaf_cert.validTo})`
    );
  }

  const signature_bytes = Buffer.from(proof_bundle.signature_b64, "base64");
  verify_nonce_signature(nonce_bytes, signature_bytes, leaf_cert);

  // Extract custom extensions from the leaf certificate
  const trust_tier_raw = extract_custom_extension_value_from_raw_der(leaf_cert, ONEID_OID_TRUST_TIER);
  const enrolled_at_raw = extract_custom_extension_value_from_raw_der(leaf_cert, ONEID_OID_ENROLLED_AT);
  const hardware_locked_raw = extract_custom_extension_value_from_raw_der(leaf_cert, ONEID_OID_HARDWARE_LOCKED);

  const verified_trust_tier = trust_tier_raw ? trust_tier_raw.toString("utf-8") : proof_bundle.trust_tier;
  const verified_enrolled_at = enrolled_at_raw ? enrolled_at_raw.toString("utf-8") : "";
  const verified_hardware_locked = hardware_locked_raw ? hardware_locked_raw[0] === 0x01 : false;

  // Try to extract agent_id from SAN URI
  let verified_agent_id = proof_bundle.agent_id;
  const san_string = leaf_cert.subjectAltName ?? "";
  const uri_match = san_string.match(/URI:urn:oneid:agent:([^\s,]+)/);
  if (uri_match) {
    verified_agent_id = uri_match[1]!;
  }

  return {
    agent_id: verified_agent_id,
    trust_tier: verified_trust_tier,
    enrolled_at: verified_enrolled_at,
    hardware_locked: verified_hardware_locked,
    chain_valid: true,
  };
}
