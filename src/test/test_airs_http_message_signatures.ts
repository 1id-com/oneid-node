/**
 * AIRS proof of possession (registry-04 "HTTP Message Signatures", RFC 9421):
 * sign_request / verify_request round trips for every AIRS key type, every
 * rejection the profile requires, the known answers shared with the Python
 * implementation, and an end-to-end signed request through the SDK's own
 * API client against a local HTTP server (OWN-038).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as http from "node:http";
import type { AddressInfo } from "node:net";

import * as airs from "../airsHttpMessageSignatures.js";
import { build_airs_request_signer_for_enrolled_key } from "../auth.js";
import { OneIDAPIClient } from "../client.js";
import type { Token } from "../identity.js";

const TARGET_URI = "https://1id.com/api/v1/proof/sd-jwt/message?format=compact";
const BODY = Buffer.from(JSON.stringify({ message_binding: "abc" }), "utf8");

function key_and_signer(kind: "rsa" | "p256" | "ed25519"): { jwk: airs.ConfirmationJwk; signer: airs.AirsRequestSigner } {
  if (kind === "rsa") {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    return { jwk: publicKey.export({ format: "jwk" }) as airs.ConfirmationJwk,
             signer: async (base) => crypto.sign("sha256", base, privateKey) };
  }
  if (kind === "p256") {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    return { jwk: publicKey.export({ format: "jwk" }) as airs.ConfirmationJwk,
             signer: async (base) => crypto.sign("sha256", base, { key: privateKey, dsaEncoding: "ieee-p1363" }) };
  }
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return { jwk: publicKey.export({ format: "jwk" }) as airs.ConfirmationJwk,
           signer: async (base) => crypto.sign(null, base, privateKey) };
}

function nonce_ledger(): (nonce: string) => boolean {
  const seen = new Set<string>();
  return (nonce: string) => { const already = seen.has(nonce); seen.add(nonce); return already; };
}

async function signed(kind: "rsa" | "p256" | "ed25519" = "p256", body: Buffer | null = BODY, options: { created?: number } = {}) {
  const { jwk, signer } = key_and_signer(kind);
  const headers: Record<string, string> = { "Authorization": "Bearer eyJhbGciOi.token.sig", "Content-Type": "application/json" };
  Object.assign(headers, await airs.sign_request("POST", TARGET_URI, headers, body, signer, { ...options, confirmation_jwk: jwk }));
  return { jwk, headers };
}

test("round trip for every AIRS key type", async () => {
  for (const kind of ["rsa", "p256", "ed25519"] as const) {
    const { jwk, headers } = await signed(kind);
    await airs.verify_request("POST", TARGET_URI, headers, BODY, jwk, nonce_ledger());
  }
});

test("bearer-only presentation is rejected", async () => {
  const { jwk } = key_and_signer("p256");
  await assert.rejects(airs.verify_request("GET", TARGET_URI, { Authorization: "Bearer t" }, Buffer.alloc(0), jwk, nonce_ledger()), /bearer/);
});

test("method, target uri, body, authorization and content-type are all protected", async () => {
  const { jwk, headers } = await signed();
  await assert.rejects(airs.verify_request("PUT", TARGET_URI, headers, BODY, jwk, nonce_ledger()));
  await assert.rejects(airs.verify_request("POST", TARGET_URI + "&x=1", headers, BODY, jwk, nonce_ledger()));
  await assert.rejects(airs.verify_request("POST", TARGET_URI, headers, Buffer.concat([BODY, Buffer.from(" ")]), jwk, nonce_ledger()));
  await assert.rejects(airs.verify_request("POST", TARGET_URI, { ...headers, Authorization: "Bearer other" }, BODY, jwk, nonce_ledger()));
  await assert.rejects(airs.verify_request("POST", TARGET_URI, { ...headers, "Content-Type": "text/plain" }, BODY, jwk, nonce_ledger()));
});

test("another key, a stale or future signature and a replay are rejected; a bad signature burns no nonce", async () => {
  const { headers } = await signed();
  const other = key_and_signer("p256");
  const ledger = nonce_ledger();
  await assert.rejects(airs.verify_request("POST", TARGET_URI, headers, BODY, other.jwk, ledger), /keyid|does not verify/);
  const now = Math.floor(Date.now() / 1000);
  const stale = await signed("p256", BODY, { created: now - 120 });
  await assert.rejects(airs.verify_request("POST", TARGET_URI, stale.headers, BODY, stale.jwk, nonce_ledger()), /older/);
  const future = await signed("p256", BODY, { created: now + 60 });
  await assert.rejects(airs.verify_request("POST", TARGET_URI, future.headers, BODY, future.jwk, nonce_ledger()), /future/);
  const fresh = await signed();
  const fresh_ledger = nonce_ledger();
  await airs.verify_request("POST", TARGET_URI, fresh.headers, BODY, fresh.jwk, fresh_ledger);
  await assert.rejects(airs.verify_request("POST", TARGET_URI, fresh.headers, BODY, fresh.jwk, fresh_ledger), /replay/);
});

test("DER ECDSA signatures (PIV, Secure Enclave) convert to r||s", async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const data = Buffer.from("x");
  const der = crypto.sign("sha256", data, { key: privateKey, dsaEncoding: "der" });
  const raw = airs.convert_der_ecdsa_signature_to_rfc9421_raw_r_and_s(der);
  assert.equal(raw.length, 64);
  assert.ok(crypto.verify("sha256", data, { key: publicKey, dsaEncoding: "ieee-p1363" }, raw));
});

test("known answers shared with the Python implementation (RFC 7638, RFC 9530, signature base)", () => {
  assert.equal(airs.compute_rfc7638_jwk_sha256_thumbprint({
    kty: "RSA", e: "AQAB",
    n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP" +
       "ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY" +
       "368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0f" +
       "M4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  }), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
  assert.equal(airs.compute_content_digest_header_value_for_request_body(Buffer.from('{"hello": "world"}')),
    "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:");
  const covered: Array<[string, string]> = [["@method", "POST"], ["@target-uri", "https://1id.com/api/v1/x?y=1"],
    ["authorization", "Bearer abc"], ["content-digest", "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"]];
  const parameters = airs.serialize_airs_signature_parameters(covered.map(([name]) => name), 1790000000, "n0nce");
  assert.equal(airs.build_airs_signature_base(covered, parameters).toString("utf8"),
    '"@method": POST\n' +
    '"@target-uri": https://1id.com/api/v1/x?y=1\n' +
    '"authorization": Bearer abc\n' +
    '"content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n' +
    '"@signature-params": ("@method" "@target-uri" "authorization" "content-digest");created=1790000000;nonce="n0nce";tag="airs-pop"');
});

test("a drifting agent clock is corrected with the token's iat", async () => {
  const { jwk, signer } = key_and_signer("p256");
  const now = Date.now() / 1000;
  const payload = Buffer.from(JSON.stringify({ iat: Math.floor(now) })).toString("base64url");
  const access_token = `h.${payload}.s`;
  const local_clock_ahead_seconds = 45;
  const offset = airs.server_clock_offset_seconds_from_access_token(access_token, now + local_clock_ahead_seconds);
  assert.ok(Math.abs(offset + local_clock_ahead_seconds) <= 1);
  const token = { access_token, token_type: "Bearer", airs_request_signer: signer, confirmation_jwk: jwk,
                  server_clock_offset_seconds: offset };
  const real_now = Date.now;
  let headers: Record<string, string>;
  try {
    Date.now = () => real_now() + local_clock_ahead_seconds * 1000;  // the agent's fast clock
    headers = await airs.build_sender_constrained_request_headers(token, "GET", TARGET_URI, null);
  } finally {
    Date.now = real_now;
  }
  await airs.verify_request("GET", TARGET_URI, headers, Buffer.alloc(0), jwk, nonce_ledger());
});

test("the SDK API client sends a Token sender-constrained (end to end, declared-key signer)", async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as airs.ConfirmationJwk;
  const token: Token = {
    access_token: "header.payload.sig", token_type: "Bearer", expires_at: new Date(Date.now() + 300000),
    refresh_token: null, confirmation_jwk: jwk,
    airs_request_signer: build_airs_request_signer_for_enrolled_key("declared", {
      software_private_key_pem: privateKey.export({ type: "pkcs8", format: "pem" }).toString() }),
  };
  const captured: { headers?: http.IncomingHttpHeaders; body?: Buffer; url?: string } = {};
  const server = http.createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      captured.headers = request.headers; captured.body = Buffer.concat(chunks); captured.url = request.url;
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ ok: true, data: {} }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    await new OneIDAPIClient(base).make_authenticated_request("POST", "/api/v1/identity/devices?x=1", token, { a: 1 });
    assert.equal(captured.headers!["authorization"], "Bearer header.payload.sig");
    const flat: Record<string, string> = {};
    for (const [name, value] of Object.entries(captured.headers!)) { flat[name] = String(value); }
    await airs.verify_request("POST", base + captured.url, flat, captured.body!, jwk, nonce_ledger());
  } finally {
    server.close();
  }
});
