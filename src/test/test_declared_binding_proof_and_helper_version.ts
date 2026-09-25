/**
 * 1id 3.0.1: declared-tier Binding-Proof Authentication (registry draft: a
 * static client_secret MUST NOT substitute for binding proof; external review
 * 072 #6) against a local stand-in Registrar that verifies the signature and
 * the RFC 7638 thumbprint, and the helper minimum-version gate (OWN-026).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as http from "node:http";
import type { AddressInfo } from "node:net";

import { authenticate_with_declared_software_key } from "../auth.js";
import { parse_version_triple, MINIMUM_ONEID_ENROLL_HELPER_VERSION } from "../helper.js";
import type { StoredCredentials } from "../credentials.js";

function rfc7638_thumbprint_of_ec_p256(public_key: crypto.KeyObject): string {
  const jwk = public_key.export({ format: "jwk" }) as { crv: string; x: string; y: string };
  const canonical = `{"crv":"${jwk.crv}","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
  return crypto.createHash("sha256").update(canonical).digest("base64url");
}

async function with_stand_in_registrar(
  enrolled_public_key: crypto.KeyObject,
  run: (base_url: string, requests: Array<Record<string, unknown>>) => Promise<void>,
): Promise<void> {
  const nonce = crypto.randomBytes(32);
  const requests: Array<Record<string, unknown>> = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      const parsed = JSON.parse(body || "{}") as Record<string, unknown>;
      requests.push({ path: request.url, ...parsed });
      response.setHeader("Content-Type", "application/json");
      if (request.url === "/api/v1/auth/challenge") {
        response.end(JSON.stringify({ ok: true, data: { challenge_id: "ch_t", nonce_b64: nonce.toString("base64") } }));
        return;
      }
      const presented = crypto.createPublicKey(parsed.public_key_pem as string);
      const same_key = rfc7638_thumbprint_of_ec_p256(presented) === rfc7638_thumbprint_of_ec_p256(enrolled_public_key);
      const signature_ok = crypto.verify("sha256", nonce, { key: presented, dsaEncoding: "der" },
        Buffer.from(parsed.signature_b64 as string, "base64"));
      if (!same_key || !signature_ok) {
        response.statusCode = 401;
        response.end(JSON.stringify({ ok: false, error: { code: "SIGNATURE_INVALID", message: "not the enrolled key" } }));
        return;
      }
      response.end(JSON.stringify({ ok: true, data: { authenticated: true, tokens: { access_token: "AT", expires_in: 300 } } }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    await run(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, requests);
  } finally {
    server.close();
  }
}

function declared_credentials(private_key: crypto.KeyObject, base_url: string): StoredCredentials {
  return {
    client_id: "id-tsthj-zhshb-sqpck-bghgw",
    client_secret: "test-secret-that-must-never-be-sent",
    token_endpoint: `${base_url}/realms/agents/protocol/openid-connect/token`,
    api_base_url: base_url,
    trust_tier: "declared",
    key_algorithm: "ecdsa-p256",
    private_key_pem: private_key.export({ type: "pkcs8", format: "pem" }).toString(),
  } as StoredCredentials;
}

test("declared identity signs the challenge with its enrolled key; no secret is sent", async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  await with_stand_in_registrar(publicKey, async (base_url, requests) => {
    const token = await authenticate_with_declared_software_key(declared_credentials(privateKey, base_url));
    assert.equal(token.access_token, "AT");
    assert.deepEqual(requests.map((request) => request.path), ["/api/v1/auth/challenge", "/api/v1/auth/verify"]);
    assert.equal(requests[0].device_type, "declared");
    assert.ok(!JSON.stringify(requests).includes("test-secret-that-must-never-be-sent"));
  });
});

test("a key other than the enrolled one is rejected", async () => {
  const enrolled = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const other = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  await with_stand_in_registrar(enrolled.publicKey, async (base_url) => {
    await assert.rejects(authenticate_with_declared_software_key(declared_credentials(other.privateKey, base_url)));
  });
});

test("helper version parsing and the 2.2.0 minimum", () => {
  assert.deepEqual(parse_version_triple("2.1.0"), [2, 1, 0]);
  assert.deepEqual(parse_version_triple("v2.10.3"), [2, 10, 3]);
  assert.deepEqual(parse_version_triple(null), [0, 0, 0]);
  assert.deepEqual(MINIMUM_ONEID_ENROLL_HELPER_VERSION, [2, 2, 0]);
});
