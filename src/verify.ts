/**
 * 1id Peer Identity Verification -- the AIRS online authority model.
 *
 * Rebuilt 2026-09-26 on the drafts' authority model (registry-04 / resolution /
 * email-hardware-attestation "Registrar Binding JWS"), replacing the old offline
 * certificate model (AUD-F05, F06, F32, F33, F69, F70, F86). Same protocol and
 * checks as the Python SDK (oneid/verify.py); bundles are interchangeable.
 *
 * Protocol:
 *   1. The verifier generates a random nonce (at least 16 bytes).
 *   2. The prover calls signChallenge(nonce) -> IdentityProofBundle: a signature
 *      over the nonce by the ENROLLED key of its local signing device, plus the
 *      Registrar Binding JWS for that key (iss, sub = the aid URN, cnf.jwk,
 *      aid.trust_tier), the aid URN and the algorithm.
 *   3. The verifier calls verifyPeerIdentity(nonce, bundle):
 *        a. resolve the aid at the AIRS Registry (RDAP): the answer must name
 *           exactly this aid and be operational (currentIssuer, hardwareLocked,
 *           registration date);
 *        b. the binding JWS: typ, asymmetric alg, sub == aid, iat/exp current,
 *           cnf.jwk public only, iss == currentIssuer, signed by a key from THAT
 *           issuer's RFC 8414 metadata jwks_uri (never from the bundle);
 *        c. the nonce signature with cnf.jwk.
 *      Trust tier comes only from the Registrar-signed binding and identity facts
 *      only from the Registry -- never from the bundle.
 *
 * Online by design (a decommissioned identity fails). For air-gapped use pass
 * current_issuer_resolver / issuer_jwk_set_provider with pre-fetched answers.
 */

import * as crypto from "node:crypto";
import { load_credentials, local_signing_device_type_for_credentials, type StoredCredentials } from "./credentials.js";
import { NotEnrolledError, OneIDError } from "./exceptions.js";
import { sign_challenge_with_private_key } from "./keys.js";

export const AIRS_RDAP_BASE_URL = "https://airs.1id.biz";
export const REGISTRAR_BINDING_JWS_TYP = "airs-email-binding+jwt";
const ACCEPTED_BINDING_JWS_ALGORITHMS = ["ES256", "RS256", "PS256"];
const NETWORK_TIMEOUT_MILLISECONDS = 10_000;
const RFC8414_JWK_SET_CACHE_MILLISECONDS = 300_000;
const issuer_jwk_set_cache = new Map<string, { fetched_at: number; keys: Array<Record<string, unknown>> }>();
const AID_URN_PATTERN = /^urn:aid:[a-z0-9-]+:id-[a-z]{5}(-[a-z]{5}){3}$/;
const VALID_TRUST_TIERS = ["sovereign", "portable", "enclave", "virtual", "declared"];

export class PeerVerificationError extends OneIDError {
  constructor(message: string, error_code: string = "PEER_VERIFICATION_ERROR") {
    super(message, error_code);
    this.name = "PeerVerificationError";
  }
}

/** The peer's identity authority could not be established: the Registry does not
 * resolve the aid to an operational identity, or the Registrar binding is invalid. */
export class RegistrarAuthorityValidationError extends PeerVerificationError {
  constructor(message: string) {
    super(message, "REGISTRAR_AUTHORITY_VALIDATION_ERROR");
    this.name = "RegistrarAuthorityValidationError";
  }
}

/** The old certificate-model name, kept so existing catch/instanceof code works. */
export const CertificateChainValidationError = RegistrarAuthorityValidationError;
export type CertificateChainValidationError = RegistrarAuthorityValidationError;

/** Registry resolution or issuer key retrieval could not complete (network,
 * timeout, HTTP 429/5xx): neither a pass nor a permanent failure -- retry. */
export class PeerVerificationTemporarilyUnavailableError extends PeerVerificationError {
  constructor(message: string) {
    super(message, "PEER_VERIFICATION_TEMPORARILY_UNAVAILABLE");
    this.name = "PeerVerificationTemporarilyUnavailableError";
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

/** Assembled by the prover, sent to the verifier (same JSON as Python's to_dict()). */
export interface IdentityProofBundle {
  signature_b64: string;
  agent_identity_urn: string;
  registrar_binding_jws: string;
  algorithm: string;
  agent_id?: string;
  /** The prover's claim; informational only (never trusted). */
  trust_tier?: string;
  /** Carried for SDK <= 3.1.1 verifiers; not used. */
  certificate_chain_pem?: string;
}

/** Every field comes from the Registry (RDAP) or the Registrar-signed binding. */
export interface VerifiedPeerIdentity {
  agent_id: string;
  trust_tier: string;
  enrolled_at: string;
  hardware_locked: boolean;
  /** True: the Registry -> issuer -> binding -> key chain verified. */
  chain_valid: boolean;
  agent_identity_urn: string;
  issuer: string;
  registrar_binding_expires_at: number;
}

export interface RegistryResolutionOfAgentIdentity {
  current_issuer: string;
  hardware_locked: boolean;
  registered_at: string;
  max_active_trust_tier: string;
}

export interface VerifyPeerIdentityOptions {
  current_issuer_resolver?: (aid: string) => Promise<RegistryResolutionOfAgentIdentity> | RegistryResolutionOfAgentIdentity;
  issuer_jwk_set_provider?: (issuer: string) => Promise<Array<Record<string, unknown>>> | Array<Record<string, unknown>>;
  reference_time_unix?: number;
  max_clock_skew_seconds?: number;
}

// ---------------------------------------------------------------------------
// Prover side
// ---------------------------------------------------------------------------

export function determine_signing_algorithm_name(creds: StoredCredentials): string {
  const algo = (creds.key_algorithm ?? "").toLowerCase();
  if (algo.includes("ed25519")) { return "EdDSA"; }
  if (algo.includes("p-384") || algo.includes("p384") || algo.includes("ecdsa-p384")) { return "ES384"; }
  if (algo.includes("p-256") || algo.includes("p256") || algo.includes("ecdsa") || algo.includes("piv")) { return "ES256"; }
  if (algo.includes("rsa") || algo.includes("tpm-ak")) { return "RS256"; }
  return "RS256";
}

async function sign_with_tpm(nonce_bytes: Buffer, ak_handle: string): Promise<{ signature_bytes: Buffer; algorithm: string }> {
  const { sign_challenge_with_tpm } = await import("./helper.js");
  const result = await sign_challenge_with_tpm(nonce_bytes.toString("base64"), ak_handle);
  const algorithm_raw = (result["algorithm"] as string) ?? "RSASSA-SHA256";
  return {
    signature_bytes: Buffer.from((result["signature_b64"] as string) ?? "", "base64"),
    algorithm: algorithm_raw.toUpperCase().includes("RSA") ? "RS256" : algorithm_raw,
  };
}

async function sign_with_piv(nonce_bytes: Buffer, piv_serial_number?: number): Promise<{ signature_bytes: Buffer; algorithm: string }> {
  const { sign_challenge_with_piv } = await import("./helper.js");
  const result = await sign_challenge_with_piv(nonce_bytes.toString("base64"), piv_serial_number);
  const algorithm_raw = (result["algorithm"] as string) ?? "ECDSA-SHA256";
  return {
    signature_bytes: Buffer.from((result["signature_b64"] as string) ?? "", "base64"),
    algorithm: algorithm_raw.toUpperCase().includes("ECDSA") ? "ES256" : algorithm_raw,
  };
}

async function sign_with_enclave(
  nonce_bytes: Buffer,
  enclave_key_data_representation_b64: string | null | undefined,
): Promise<{ signature_bytes: Buffer; algorithm: string }> {
  const { sign_challenge_with_enclave } = await import("./helper.js");
  const { restore_enclave_key_file_from_credentials_if_missing } = await import("./enroll.js");
  if (enclave_key_data_representation_b64) {
    restore_enclave_key_file_from_credentials_if_missing(enclave_key_data_representation_b64);
  }
  const result = await sign_challenge_with_enclave(nonce_bytes.toString("base64"));
  return { signature_bytes: Buffer.from((result["signature_b64"] as string) ?? "", "base64"), algorithm: "ES256" };
}

/**
 * Sign a verifier-provided nonce and assemble a proof bundle. The ENROLLED LOCAL
 * DEVICE signs (hsm_key_reference first, tier only as fallback -- the rule login
 * and Mode 1 use) unless signing_device_type selects one. The bundle carries the
 * Registrar Binding JWS for exactly the key that signed. Same as Python sign_challenge().
 */
export async function signChallenge(
  nonce_bytes: Buffer,
  signing_device_type?: "tpm" | "piv" | "enclave" | "software" | null,
  piv_serial_number?: number,
): Promise<IdentityProofBundle> {
  const { certificate_chain_leaf_key_verifies_mode1_signature, public_key_jwk_of_certificate_chain_leaf, _fetch_binding_jws } =
    await import("./attestation.js");
  const { get_token } = await import("./auth.js");
  const creds = load_credentials();
  if (!creds.identity_certificate_chain_pem) {
    throw new MissingIdentityCertificateError(
      "No identity certificate chain found in credentials. Re-enroll or recover your identity to obtain a certificate.");
  }
  if (!creds.agent_identity_urn) {
    throw new NotEnrolledError("These credentials have no agent identity URN; re-enroll to obtain one.");
  }

  const device_type = signing_device_type ?? local_signing_device_type_for_credentials(creds);
  let signature_bytes: Buffer;
  let algorithm: string;
  if (device_type === "tpm") {
    ({ signature_bytes, algorithm } = await sign_with_tpm(nonce_bytes, creds.hsm_key_reference ?? ""));
  } else if (device_type === "piv") {
    ({ signature_bytes, algorithm } = await sign_with_piv(nonce_bytes, piv_serial_number));
  } else if (device_type === "enclave") {
    ({ signature_bytes, algorithm } = await sign_with_enclave(nonce_bytes, creds.enclave_key_data_representation_b64));
  } else if (device_type === "software" && creds.private_key_pem) {
    signature_bytes = sign_challenge_with_private_key(creds.private_key_pem, nonce_bytes);
    algorithm = determine_signing_algorithm_name(creds);
  } else {
    throw new NotEnrolledError(
      "Cannot sign challenge: no signing key available. " +
      "Credentials exist but contain neither a private key nor an HSM reference.");
  }
  if (!ACCEPTED_BINDING_JWS_ALGORITHMS.includes(algorithm)) {
    throw new PeerVerificationError(
      `A ${algorithm} key cannot carry a Registrar binding (ES256 / RS256 / PS256 only); enroll a declared ` +
      "identity with key_algorithm 'ecdsa-p256' (the default) or use a hardware tier.");
  }

  const candidate_chains: string[] = [];
  for (const chain_data of Object.values(creds.device_certificate_chains ?? {})) {
    const chain_pem = typeof chain_data === "string" ? chain_data : (chain_data as Record<string, unknown> | null)?.["certificate_chain_pem"];
    if (typeof chain_pem === "string" && chain_pem && !candidate_chains.includes(chain_pem)) { candidate_chains.push(chain_pem); }
  }
  candidate_chains.push(creds.identity_certificate_chain_pem);
  const signing_chain = candidate_chains.find((chain) =>
    certificate_chain_leaf_key_verifies_mode1_signature(chain, nonce_bytes, signature_bytes, algorithm));
  if (signing_chain === undefined) {
    throw new PeerVerificationError(
      "No stored certificate chain holds the key that signed; re-sync device certificates " +
      "(sync_device_certificate_chains_from_server) or re-enroll.");
  }
  const signing_key_jwk = public_key_jwk_of_certificate_chain_leaf(signing_chain);
  if (signing_key_jwk == null) {
    throw new PeerVerificationError("The signing key cannot be expressed as a JWK for the Registrar binding.");
  }
  const token = await get_token(false, creds);
  const binding_jws = await _fetch_binding_jws(creds.api_base_url || "https://1id.com", token, signing_key_jwk);
  if (!binding_jws) {
    throw new PeerVerificationError("The Registrar did not issue a binding for the signing key; try again.");
  }
  return {
    signature_b64: signature_bytes.toString("base64"),
    agent_identity_urn: creds.agent_identity_urn,
    registrar_binding_jws: binding_jws,
    algorithm,
    agent_id: creds.client_id,
    trust_tier: creds.trust_tier ?? "",
    certificate_chain_pem: signing_chain,
  };
}

// ---------------------------------------------------------------------------
// Verifier side
// ---------------------------------------------------------------------------

class PermanentHttpError extends Error {
  constructor(public readonly status: number, url: string) { super(`${url}: HTTP ${status}`); }
}

async function fetch_json_document(url: string, accept: string = "application/json"): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(url, { headers: { Accept: accept }, signal: AbortSignal.timeout(NETWORK_TIMEOUT_MILLISECONDS) });
  } catch (network_error) {
    throw new PeerVerificationTemporarilyUnavailableError(`${url}: ${network_error}`);
  }
  if (response.status === 429 || response.status >= 500) {
    throw new PeerVerificationTemporarilyUnavailableError(`${url}: HTTP ${response.status}`);
  }
  if (!response.ok) { throw new PermanentHttpError(response.status, url); }
  return await response.json();
}

/**
 * Resolve an aid at the AIRS Registry (RDAP) with the Resolution draft's checks:
 * the answer names exactly this aid and it is operational. Same as Python
 * resolve_agent_identity_at_airs_registry().
 */
export async function resolve_agent_identity_at_airs_registry(agent_identity_urn: string): Promise<RegistryResolutionOfAgentIdentity> {
  const rdap_url = `${AIRS_RDAP_BASE_URL}/rdap/aid_identity/${encodeURIComponent(agent_identity_urn)}`;
  let data: Record<string, any>;
  try {
    data = await fetch_json_document(rdap_url, "application/rdap+json") as Record<string, any>;
  } catch (lookup_error) {
    if (lookup_error instanceof PermanentHttpError) {
      throw new RegistrarAuthorityValidationError(`AIRS Registry does not resolve '${agent_identity_urn}' (HTTP ${lookup_error.status})`);
    }
    if (lookup_error instanceof SyntaxError) {
      throw new RegistrarAuthorityValidationError(`RDAP answer for '${agent_identity_urn}' is not JSON`);
    }
    throw lookup_error;
  }
  if (data == null || typeof data !== "object" || data["objectClassName"] !== "aid_agentIdentity") {
    throw new RegistrarAuthorityValidationError(`RDAP answer for '${agent_identity_urn}' is not an aid_agentIdentity object`);
  }
  const aid_data = data["aid_data"];
  if (aid_data == null || typeof aid_data !== "object") {
    throw new RegistrarAuthorityValidationError(`RDAP answer for '${agent_identity_urn}' has no aid_data`);
  }
  if (data["handle"] !== agent_identity_urn || aid_data["canonical"] !== agent_identity_urn) {
    throw new RegistrarAuthorityValidationError(`RDAP answer names '${aid_data["canonical"]}', not the requested '${agent_identity_urn}'`);
  }
  if (aid_data["lifecycleState"] !== "operational") {
    throw new RegistrarAuthorityValidationError(
      `AIRS identity '${agent_identity_urn}' has lifecycleState '${aid_data["lifecycleState"]}' (must be operational)`);
  }
  const current_issuer = aid_data["currentIssuer"];
  if (typeof current_issuer !== "string" || !current_issuer) {
    throw new RegistrarAuthorityValidationError(`AIRS identity '${agent_identity_urn}' has no current issuer`);
  }
  const registration_event = (Array.isArray(data["events"]) ? data["events"] : [])
    .find((event: any) => event && event["eventAction"] === "registration");
  return {
    current_issuer,
    hardware_locked: aid_data["hardwareLocked"] === true,
    registered_at: registration_event?.["eventDate"] ?? "",
    max_active_trust_tier: aid_data["maxActiveTrustTier"] ?? "",
  };
}

/** The issuer's signing keys, ONLY from its RFC 8414 metadata jwks_uri (metadata
 * issuer must equal the issuer). Cached per issuer for 5 minutes. */
export async function fetch_issuer_jwk_set_via_rfc8414_metadata(issuer_uri: string): Promise<Array<Record<string, unknown>>> {
  const cached = issuer_jwk_set_cache.get(issuer_uri);
  if (cached && Date.now() - cached.fetched_at < RFC8414_JWK_SET_CACHE_MILLISECONDS) { return cached.keys; }
  let parsed_issuer: URL;
  try { parsed_issuer = new URL(issuer_uri); } catch {
    throw new RegistrarAuthorityValidationError(`issuer '${issuer_uri}' is not a URL`);
  }
  if (parsed_issuer.protocol !== "https:" || parsed_issuer.search || parsed_issuer.hash) {
    throw new RegistrarAuthorityValidationError(`issuer '${issuer_uri}' is not an https issuer identifier (RFC 8414)`);
  }
  const metadata_url = `https://${parsed_issuer.host}/.well-known/oauth-authorization-server${parsed_issuer.pathname.replace(/\/+$/, "")}`;
  const load = async (url: string, what: string): Promise<Record<string, any>> => {
    try {
      return await fetch_json_document(url) as Record<string, any>;
    } catch (load_error) {
      if (load_error instanceof PermanentHttpError) {
        throw new RegistrarAuthorityValidationError(`${what} unavailable (HTTP ${load_error.status})`);
      }
      throw load_error;
    }
  };
  const metadata = await load(metadata_url, `RFC 8414 metadata for '${issuer_uri}'`);
  if (metadata["issuer"] !== issuer_uri) {
    throw new RegistrarAuthorityValidationError(`RFC 8414 metadata issuer '${metadata["issuer"]}' does not equal '${issuer_uri}'`);
  }
  const jwks_uri = metadata["jwks_uri"];
  if (typeof jwks_uri !== "string" || !jwks_uri.startsWith("https://")) {
    throw new RegistrarAuthorityValidationError(`RFC 8414 metadata for '${issuer_uri}' has no https jwks_uri`);
  }
  const jwk_set = await load(jwks_uri, `JWK Set ${jwks_uri}`);
  const keys = jwk_set?.["keys"];
  if (!Array.isArray(keys)) { throw new RegistrarAuthorityValidationError(`JWK Set ${jwks_uri} has no keys array`); }
  issuer_jwk_set_cache.set(issuer_uri, { fetched_at: Date.now(), keys });
  return keys;
}

function public_key_from_jwk(jwk: Record<string, unknown>): crypto.KeyObject {
  if (["d", "p", "q", "dp", "dq", "qi", "k"].some((member) => member in jwk)) {
    throw new Error("JWK contains private key members");
  }
  if (jwk["kty"] === "EC" && !["P-256", "P-384"].includes(String(jwk["crv"]))) {
    throw new Error(`unsupported EC curve '${jwk["crv"]}'`);
  }
  if (jwk["kty"] !== "EC" && jwk["kty"] !== "RSA") { throw new Error(`unsupported JWK kty '${jwk["kty"]}'`); }
  const public_members = jwk["kty"] === "EC"
    ? { kty: "EC", crv: jwk["crv"], x: jwk["x"], y: jwk["y"] }
    : { kty: "RSA", n: jwk["n"], e: jwk["e"] };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- @types/node lacks a JsonWebKey input type here
  return crypto.createPublicKey({ key: public_members as any, format: "jwk" });
}

function jws_signature_is_valid(public_key: crypto.KeyObject, alg: string, signing_input: Buffer, signature: Buffer): boolean {
  try {
    if (alg === "ES256" && public_key.asymmetricKeyType === "ec" && signature.length === 64) {
      return crypto.verify("sha256", signing_input, { key: public_key, dsaEncoding: "ieee-p1363" }, signature);
    }
    if (alg === "RS256" && public_key.asymmetricKeyType === "rsa") {
      return crypto.verify("sha256", signing_input, public_key, signature);
    }
    if (alg === "PS256" && public_key.asymmetricKeyType === "rsa") {
      return crypto.verify("sha256", signing_input,
        { key: public_key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);
    }
    return false;
  } catch {
    return false;
  }
}

function nonce_signature_is_valid(public_key: crypto.KeyObject, algorithm: string, nonce_bytes: Buffer, signature: Buffer): boolean {
  try {
    if (public_key.asymmetricKeyType === "ec") {
      return crypto.verify("sha256", nonce_bytes,
        { key: public_key, dsaEncoding: signature.length === 64 ? "ieee-p1363" : "der" }, signature);
    }
    if (public_key.asymmetricKeyType === "rsa" && algorithm === "PS256") {
      return crypto.verify("sha256", nonce_bytes,
        { key: public_key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);
    }
    if (public_key.asymmetricKeyType === "rsa") { return crypto.verify("sha256", nonce_bytes, public_key, signature); }
    if (public_key.asymmetricKeyType === "ed25519") { return crypto.verify(null, nonce_bytes, public_key, signature); }
    return false;
  } catch {
    return false;
  }
}

function base64url_json(segment: string): Record<string, any> {
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf-8")) as Record<string, any>;
}

/**
 * Validate another agent's proof bundle on the AIRS authority model (see the file
 * header). api_base_url is accepted for compatibility and unused: the authority
 * comes from the AIRS Registry and the issuer it names. Same as Python
 * verify_peer_identity().
 */
export async function verifyPeerIdentity(
  nonce_bytes: Buffer,
  proof_bundle: IdentityProofBundle,
  _api_base_url?: string,
  options: VerifyPeerIdentityOptions = {},
): Promise<VerifiedPeerIdentity> {
  if (nonce_bytes.length < 16) { throw new PeerVerificationError("The verifier nonce must be at least 16 bytes"); }
  const aid = proof_bundle.agent_identity_urn ?? "";
  if (!AID_URN_PATTERN.test(aid)) {
    throw new PeerVerificationError(`Proof bundle carries no valid agent identity URN ('${aid}')`);
  }
  if (!proof_bundle.registrar_binding_jws) {
    throw new RegistrarAuthorityValidationError(
      "Proof bundle carries no Registrar binding (made by an SDK older than 3.1.2?); ask the peer to upgrade and sign again.");
  }
  const parts = proof_bundle.registrar_binding_jws.split(".");
  if (parts.length !== 3) { throw new RegistrarAuthorityValidationError("Registrar binding is not a compact JWS"); }
  let header: Record<string, any>;
  let payload: Record<string, any>;
  try {
    header = base64url_json(parts[0]);
    payload = base64url_json(parts[1]);
  } catch (decode_error) {
    throw new RegistrarAuthorityValidationError(`Registrar binding cannot be decoded: ${decode_error}`);
  }
  if (header["typ"] !== REGISTRAR_BINDING_JWS_TYP) {
    throw new RegistrarAuthorityValidationError(`Registrar binding typ must be '${REGISTRAR_BINDING_JWS_TYP}'`);
  }
  const jws_alg = String(header["alg"] ?? "");
  if (!ACCEPTED_BINDING_JWS_ALGORITHMS.includes(jws_alg)) {
    throw new RegistrarAuthorityValidationError(`Registrar binding alg '${jws_alg}' is not accepted`);
  }
  if (payload["sub"] !== aid) { throw new RegistrarAuthorityValidationError(`Registrar binding sub '${payload["sub"]}' is not '${aid}'`); }
  const now = Math.floor(options.reference_time_unix ?? Date.now() / 1000);
  const skew = options.max_clock_skew_seconds ?? 300;
  const issued_at = payload["iat"];
  const expires_at = payload["exp"];
  if (!Number.isInteger(issued_at) || !Number.isInteger(expires_at) || expires_at <= issued_at) {
    throw new RegistrarAuthorityValidationError("Registrar binding needs integer iat < exp");
  }
  if (issued_at > now + skew) { throw new RegistrarAuthorityValidationError("Registrar binding iat is in the future"); }
  if (expires_at < now - skew) { throw new RegistrarAuthorityValidationError("Registrar binding has expired; ask the peer to sign again"); }
  const bound_jwk = payload["cnf"]?.["jwk"];
  if (bound_jwk == null || typeof bound_jwk !== "object") { throw new RegistrarAuthorityValidationError("Registrar binding has no cnf.jwk"); }
  const bound_trust_tier = String(payload["aid"]?.["trust_tier"] ?? "");
  if (!VALID_TRUST_TIERS.includes(bound_trust_tier)) {
    throw new RegistrarAuthorityValidationError(`Registrar binding carries no valid aid.trust_tier ('${bound_trust_tier}')`);
  }
  let bound_public_key: crypto.KeyObject;
  try {
    bound_public_key = public_key_from_jwk(bound_jwk);
  } catch (jwk_error) {
    throw new RegistrarAuthorityValidationError(`Registrar binding cnf.jwk is unusable: ${jwk_error}`);
  }

  // Authority: the Registry names the current issuer; the binding must be its.
  const registry_answer = await (options.current_issuer_resolver ?? resolve_agent_identity_at_airs_registry)(aid);
  if (payload["iss"] !== registry_answer.current_issuer) {
    throw new RegistrarAuthorityValidationError(
      `Registrar binding iss '${payload["iss"]}' is not the Registry's current issuer '${registry_answer.current_issuer}'`);
  }
  const issuer_keys = await (options.issuer_jwk_set_provider ?? fetch_issuer_jwk_set_via_rfc8414_metadata)(registry_answer.current_issuer);
  const signing_input = Buffer.from(`${parts[0]}.${parts[1]}`, "ascii");
  const jws_signature = Buffer.from(parts[2], "base64url");
  const binding_signature_valid = issuer_keys
    .filter((key) => key != null && typeof key === "object" && (header["kid"] == null || key["kid"] === header["kid"]))
    .some((candidate_jwk) => {
      try {
        return jws_signature_is_valid(public_key_from_jwk(candidate_jwk), jws_alg, signing_input, jws_signature);
      } catch {
        return false;
      }
    });
  if (!binding_signature_valid) {
    throw new RegistrarAuthorityValidationError(
      `Registrar binding is not signed by a key of '${registry_answer.current_issuer}' (RFC 8414 jwks_uri)`);
  }
  if (!nonce_signature_is_valid(bound_public_key, proof_bundle.algorithm, nonce_bytes, Buffer.from(proof_bundle.signature_b64, "base64"))) {
    throw new SignatureVerificationError("The nonce signature was not made by the key the Registrar bound to this identity");
  }
  return {
    agent_id: aid.slice(aid.lastIndexOf(":") + 1),
    trust_tier: bound_trust_tier,
    enrolled_at: registry_answer.registered_at,
    hardware_locked: registry_answer.hardware_locked,
    chain_valid: true,
    agent_identity_urn: aid,
    issuer: registry_answer.current_issuer,
    registrar_binding_expires_at: expires_at,
  };
}

/** Python-style names (the Python SDK's sign_challenge / verify_peer_identity). */
export const sign_challenge = signChallenge;
export const verify_peer_identity = verifyPeerIdentity;
