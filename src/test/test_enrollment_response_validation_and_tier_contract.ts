/**
 * AUD-F72: a successful enrollment response that does not name a valid identity
 * is refused and nothing is saved. AUD-F35: an explicitly requested tier is the
 * tier enrolled, or an exception (credentials of the identity that WAS created
 * are kept). Mirrors oneid-sdk tests/test_enrollment_response_validation_and_tier_contract.py.
 */
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { OneIDAPIClient } from "../client.js";
import { enroll } from "../enroll.js";
import { credentials_exist, delete_credentials } from "../credentials.js";

const isolated_config_directory = fs.mkdtempSync(path.join(os.tmpdir(), "oneid-node-test-config-"));
process.env["APPDATA"] = isolated_config_directory;
process.env["XDG_CONFIG_HOME"] = isolated_config_directory;

function good_declared_response(): Record<string, any> {
  return {
    identity: {
      agent_id: "id-xpwsb-rqgdz-vctkm-nfjhx", agent_identity_urn: "urn:aid:global:id-xpwsb-rqgdz-vctkm-nfjhx",
      handle: "@id-xpwsb-rqgdz-vctkm-nfjhx", trust_tier: "declared", registered_at: "2026-09-26T00:00:00Z",
    },
    credentials: { client_id: "id-xpwsb-rqgdz-vctkm-nfjhx" },
  };
}

async function enroll_declared_with_server_response(response: Record<string, any>): Promise<unknown> {
  const original = OneIDAPIClient.prototype.enroll_declared;
  OneIDAPIClient.prototype.enroll_declared = (async () => response) as typeof original;
  try {
    return await enroll({ request_tier: "declared" });
  } finally {
    OneIDAPIClient.prototype.enroll_declared = original;
  }
}

beforeEach(() => { if (credentials_exist()) { delete_credentials(); } });

const breakages: Array<[string, (data: Record<string, any>) => void, RegExp]> = [
  ["no identity object", (data) => { delete data.identity; }, /no identity object/],
  ["no agent id", (data) => { delete data.identity.agent_id; }, /no valid canonical identity id/],
  ["malformed agent id", (data) => { data.identity.agent_id = "not-an-id"; }, /no valid canonical identity id/],
  ["no trust tier", (data) => { delete data.identity.trust_tier; }, /no valid trust tier/],
  ["unknown trust tier", (data) => { data.identity.trust_tier = "imaginary"; }, /no valid trust tier/],
];
for (const [label, breakage, message] of breakages) {
  test(`malformed success response is refused and nothing is saved: ${label}`, async () => {
    const response = good_declared_response();
    breakage(response);
    await assert.rejects(enroll_declared_with_server_response(response), message);
    assert.equal(credentials_exist(), false);
  });
}

test("a different tier than requested throws but keeps the created identity", async () => {
  const response = good_declared_response();
  response.identity.trust_tier = "virtual";
  await assert.rejects(enroll_declared_with_server_response(response),
    /Requested trust tier 'declared' but the Registrar enrolled this device as 'virtual'/);
  assert.equal(credentials_exist(), true);
});

test("a well-formed response enrolls at the requested tier", async () => {
  const identity = await enroll_declared_with_server_response(good_declared_response()) as { trust_tier: string; canonical_id: string };
  assert.equal(identity.trust_tier, "declared");
  assert.equal(identity.canonical_id, "id-xpwsb-rqgdz-vctkm-nfjhx");
});
