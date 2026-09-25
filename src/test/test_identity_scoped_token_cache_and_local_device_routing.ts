/**
 * AUD-F55: the token cache is per identity (a second identity never receives the
 * first one's token). AUD-F66 / AUD-LOST1: the enrolled local device, not the
 * trust tier, selects PIV / TPM / Secure Enclave. Mirrors oneid-sdk
 * tests/test_identity_scoped_token_cache_and_local_device_routing.py.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as http from "node:http";
import type { AddressInfo } from "node:net";

import { get_token, clear_cached_token } from "../auth.js";
import { local_signing_device_type_for_credentials, type StoredCredentials } from "../credentials.js";

function credentials_with(fields: Partial<StoredCredentials>): StoredCredentials {
  return {
    client_id: "id-aaaaa-bbbbb-ccccc-ddddd", client_secret: "", token_endpoint: "", api_base_url: "",
    trust_tier: "declared", key_algorithm: "ecdsa-p256", ...fields,
  } as StoredCredentials;
}

test("the enrolled local binding decides the signing device; the tier is only the fallback", () => {
  assert.equal(local_signing_device_type_for_credentials(credentials_with({ trust_tier: "sovereign", hsm_key_reference: "piv-slot-9a" })), "piv");
  assert.equal(local_signing_device_type_for_credentials(credentials_with({ trust_tier: "sovereign", hsm_key_reference: "secure-enclave" })), "enclave");
  assert.equal(local_signing_device_type_for_credentials(credentials_with({ trust_tier: "portable", hsm_key_reference: "0x81000100" })), "tpm");
  assert.equal(local_signing_device_type_for_credentials(credentials_with({ trust_tier: "portable" })), "piv");
  assert.equal(local_signing_device_type_for_credentials(credentials_with({ trust_tier: "enclave" })), "enclave");
  assert.equal(local_signing_device_type_for_credentials(credentials_with({ trust_tier: "virtual" })), "tpm");
  assert.equal(local_signing_device_type_for_credentials(credentials_with({ trust_tier: "declared", private_key_pem: "PEM" })), "software");
  assert.equal(local_signing_device_type_for_credentials(credentials_with({ trust_tier: "declared" })), null);
});

test("a cached token is only returned to the identity it was issued to", async () => {
  let tokens_issued = 0;
  const server = http.createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      response.setHeader("Content-Type", "application/json");
      if (request.url === "/api/v1/auth/challenge") {
        response.end(JSON.stringify({ ok: true, data: { challenge_id: "ch", nonce_b64: crypto.randomBytes(32).toString("base64") } }));
        return;
      }
      tokens_issued += 1;
      response.end(JSON.stringify({ ok: true, data: { authenticated: true, tokens: { access_token: `AT-${tokens_issued}`, expires_in: 300 } } }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base_url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const declared_identity = (client_id: string): StoredCredentials => credentials_with({
    client_id, api_base_url: base_url, token_endpoint: `${base_url}/token`,
    private_key_pem: crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey
      .export({ type: "pkcs8", format: "pem" }).toString(),
  });
  try {
    clear_cached_token();
    const identity_a = declared_identity("id-aaaaa-aaaaa-aaaaa-aaaaa");
    const identity_b = declared_identity("id-bbbbb-bbbbb-bbbbb-bbbbb");
    const first_a = await get_token(false, identity_a);
    const second_a = await get_token(false, identity_a);
    const first_b = await get_token(false, identity_b);
    assert.equal(first_a.access_token, "AT-1");
    assert.equal(second_a.access_token, "AT-1", "identity A reuses its own cached token");
    assert.equal(first_b.access_token, "AT-2", "identity B must not receive identity A's token");
    assert.equal(tokens_issued, 2);
  } finally {
    clear_cached_token();
    server.close();
  }
});

test("the local identity reports the enrolled device type (AUD-F59)", async () => {
  const fs = await import("node:fs");
  const os = await import("node:os");
  const path = await import("node:path");
  const { save_credentials, delete_credentials } = await import("../credentials.js");
  const { whoami } = await import("../index.js");
  const isolated = fs.mkdtempSync(path.join(os.tmpdir(), "oneid-node-test-config-"));
  const saved_environment = { APPDATA: process.env["APPDATA"], XDG_CONFIG_HOME: process.env["XDG_CONFIG_HOME"] };
  process.env["APPDATA"] = isolated;
  process.env["XDG_CONFIG_HOME"] = isolated;
  try {
    const cases: Array<[Partial<StoredCredentials>, string]> = [
      [{ trust_tier: "sovereign", hsm_key_reference: "piv-slot-9a" }, "yubikey"],
      [{ trust_tier: "sovereign", hsm_key_reference: "secure-enclave" }, "secure_enclave"],
      [{ trust_tier: "virtual", hsm_key_reference: "0x81000100" }, "tpm"],
      [{ trust_tier: "declared", private_key_pem: "PEM" }, "software"],
    ];
    for (const [fields, expected_hsm_type] of cases) {
      save_credentials(credentials_with(fields));
      assert.equal(whoami().hsm_type, expected_hsm_type);
      delete_credentials();
    }
  } finally {
    process.env["APPDATA"] = saved_environment.APPDATA;
    process.env["XDG_CONFIG_HOME"] = saved_environment.XDG_CONFIG_HOME;
  }
});
