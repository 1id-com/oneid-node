/**
 * Peer verification on the AIRS authority model (rebuilt 2026-09-26; AUD-F05,
 * F06, F32, F33, F69, F70, F86; the old certificate-model tests and their empty
 * TODO hardware tests, AUD-F39, are replaced): Registry resolution -> current
 * issuer -> binding JWS signed by that issuer's key -> nonce signature by the
 * bound key. Trust tier and identity facts never come from the bundle. Mirrors
 * oneid-sdk tests/test_peer_verification_airs_authority_model.py.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";

import {
  verifyPeerIdentity,
  verify_peer_identity,
  PeerVerificationError,
  PeerVerificationTemporarilyUnavailableError,
  RegistrarAuthorityValidationError,
  CertificateChainValidationError,
  SignatureVerificationError,
  type IdentityProofBundle,
  type RegistryResolutionOfAgentIdentity,
} from "../verify.js";

const AID = "urn:aid:global:id-tstpv-aaaaa-bbbbb-ccccc";
const ISSUER = "https://issuer.example/realms/agents";

function ec_public_jwk(key: crypto.KeyObject, kid?: string): Record<string, unknown> {
  const jwk = crypto.createPublicKey(key).export({ format: "jwk" }) as Record<string, unknown>;
  const public_jwk: Record<string, unknown> = { kty: "EC", crv: jwk["crv"], x: jwk["x"], y: jwk["y"] };
  if (kid) { public_jwk["kid"] = kid; }
  return public_jwk;
}

function make_binding_jws(registrar: crypto.KeyObject, prover: crypto.KeyObject,
  overrides: Record<string, unknown> = {}, header_overrides: Record<string, unknown> = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", typ: "airs-email-binding+jwt", kid: "registrar-1", ...header_overrides };
  const payload = { iss: ISSUER, sub: AID, iat: now, exp: now + 300, cnf: { jwk: ec_public_jwk(prover) },
    aid: { trust_tier: "sovereign" }, ...overrides };
  const signing_input = `${Buffer.from(JSON.stringify(header)).toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}`;
  const signature = crypto.sign("sha256", Buffer.from(signing_input), { key: registrar, dsaEncoding: "ieee-p1363" });
  return `${signing_input}.${signature.toString("base64url")}`;
}

function new_world() {
  const registrar = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
  const prover = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
  const nonce = crypto.randomBytes(32);
  const registry_answer: RegistryResolutionOfAgentIdentity = {
    current_issuer: ISSUER, hardware_locked: true, registered_at: "2026-09-25T10:35:15Z", max_active_trust_tier: "sovereign" };
  return {
    registrar, prover, nonce,
    resolver: async () => ({ ...registry_answer }),
    jwks: async (issuer: string) => issuer === ISSUER ? [ec_public_jwk(registrar, "registrar-1")] : [],
  };
}

function bundle_for(world: ReturnType<typeof new_world>, fields: Partial<IdentityProofBundle> = {}): IdentityProofBundle {
  return {
    signature_b64: crypto.sign("sha256", world.nonce, world.prover).toString("base64"),
    agent_identity_urn: AID,
    registrar_binding_jws: make_binding_jws(world.registrar, world.prover),
    algorithm: "ES256", agent_id: "id-tstpv-aaaaa-bbbbb-ccccc", trust_tier: "declared",
    ...fields,
  };
}

async function verify(world: ReturnType<typeof new_world>, bundle: IdentityProofBundle,
  resolver: (aid: string) => Promise<RegistryResolutionOfAgentIdentity> = world.resolver) {
  return verifyPeerIdentity(world.nonce, bundle, undefined, { current_issuer_resolver: resolver, issuer_jwk_set_provider: world.jwks });
}

test("a valid bundle verifies with facts from the Registry and the binding", async () => {
  const world = new_world();
  const verified = await verify(world, bundle_for(world));
  assert.equal(verified.agent_identity_urn, AID);
  assert.equal(verified.agent_id, "id-tstpv-aaaaa-bbbbb-ccccc");
  assert.equal(verified.trust_tier, "sovereign", "from the Registrar binding, not the bundle's 'declared' claim");
  assert.equal(verified.hardware_locked, true);
  assert.equal(verified.enrolled_at, "2026-09-25T10:35:15Z");
  assert.equal(verified.issuer, ISSUER);
  assert.equal(verified.chain_valid, true);
});

test("the Python-style name is the same function", () => {
  assert.equal(verify_peer_identity, verifyPeerIdentity);
});

test("a binding from an issuer that is not the Registry's current issuer fails", async () => {
  const world = new_world();
  const binding = make_binding_jws(world.registrar, world.prover, { iss: "https://evil.example/realms/agents" });
  await assert.rejects(verify(world, bundle_for(world, { registrar_binding_jws: binding })), /not the Registry's current issuer/);
});

test("a binding signed by a key outside the issuer's JWK set fails", async () => {
  const world = new_world();
  const impostor = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
  await assert.rejects(verify(world, bundle_for(world, { registrar_binding_jws: make_binding_jws(impostor, world.prover) })),
    (error: unknown) => error instanceof RegistrarAuthorityValidationError && /not signed by a key of/.test((error as Error).message));
});

test("a nonce signed by another key fails", async () => {
  const world = new_world();
  const other = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
  await assert.rejects(verify(world, bundle_for(world, { signature_b64: crypto.sign("sha256", world.nonce, other).toString("base64") })),
    SignatureVerificationError);
});

test("a binding for another aid fails", async () => {
  const world = new_world();
  const binding = make_binding_jws(world.registrar, world.prover, { sub: "urn:aid:global:id-other-aaaaa-bbbbb-ccccc" });
  await assert.rejects(verify(world, bundle_for(world, { registrar_binding_jws: binding })), /sub/);
});

test("an expired binding fails", async () => {
  const world = new_world();
  const old = Math.floor(Date.now() / 1000) - 3600;
  const binding = make_binding_jws(world.registrar, world.prover, { iat: old - 300, exp: old });
  await assert.rejects(verify(world, bundle_for(world, { registrar_binding_jws: binding })), /expired/);
});

test("a non-operational identity fails", async () => {
  const world = new_world();
  const decommissioned = async (aid: string): Promise<RegistryResolutionOfAgentIdentity> => {
    throw new RegistrarAuthorityValidationError(`AIRS identity '${aid}' has lifecycleState 'decommissioned'`);
  };
  await assert.rejects(verify(world, bundle_for(world), decommissioned), /decommissioned/);
});

test("a Registry outage is temporary, not a pass", async () => {
  const world = new_world();
  const unreachable = async (): Promise<RegistryResolutionOfAgentIdentity> => {
    throw new PeerVerificationTemporarilyUnavailableError("RDAP: timeout");
  };
  await assert.rejects(verify(world, bundle_for(world), unreachable), PeerVerificationTemporarilyUnavailableError);
});

test("a bundle without a binding is refused (the old error name still matches)", async () => {
  const world = new_world();
  await assert.rejects(verify(world, bundle_for(world, { registrar_binding_jws: "" })),
    (error: unknown) => error instanceof CertificateChainValidationError && /no Registrar binding/.test((error as Error).message));
});

test("a wrong typ and a symmetric alg are refused", async () => {
  const world = new_world();
  await assert.rejects(verify(world, bundle_for(world, {
    registrar_binding_jws: make_binding_jws(world.registrar, world.prover, {}, { typ: "JWT" }) })), /typ/);
  await assert.rejects(verify(world, bundle_for(world, {
    registrar_binding_jws: make_binding_jws(world.registrar, world.prover, {}, { alg: "HS256" }) })), /alg/);
});

test("a short nonce is refused", async () => {
  const world = new_world();
  await assert.rejects(verifyPeerIdentity(Buffer.from("short"), bundle_for(world), undefined,
    { current_issuer_resolver: world.resolver, issuer_jwk_set_provider: world.jwks }), PeerVerificationError);
});
