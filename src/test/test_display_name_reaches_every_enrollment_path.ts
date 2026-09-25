/**
 * OWN-029: the friendly display_name reaches the server on the TPM
 * (sovereign/virtual) and PIV (portable) enrollment paths too -- it used to be
 * dropped there (only declared and enclave enrollment sent it). Mirrors oneid-sdk
 * tests/test_display_name_reaches_every_enrollment_path.py. Node's helper runs a
 * real binary (not fakeable from a test), so the client request bodies are
 * checked directly, and enroll.ts is checked to pass display_name to every
 * begin call.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import { fileURLToPath } from "node:url";

import { OneIDAPIClient } from "../client.js";

async function request_body_sent_by(call_client_method: (client: OneIDAPIClient) => Promise<unknown>): Promise<Record<string, unknown>> {
  const client_prototype = OneIDAPIClient.prototype as any;
  const original_make_request = client_prototype._make_request;
  let captured_request_body: Record<string, unknown> = {};
  client_prototype._make_request = async (_method: string, _path: string, body: Record<string, unknown>) => {
    captured_request_body = body;
    return {};
  };
  try {
    await call_client_method(new OneIDAPIClient("http://127.0.0.1:9"));
  } finally {
    client_prototype._make_request = original_make_request;
  }
  return captured_request_body;
}

test("the TPM enrollment begin request carries display_name", async () => {
  const body = await request_body_sent_by((client) =>
    client.enroll_begin("EK", "AK", "", "", undefined, "tpm", null, "sparky-test", "Sparky"));
  assert.equal(body["display_name"], "Sparky");
  assert.equal(body["requested_handle"], "sparky-test");
});

test("the PIV enrollment begin request carries display_name", async () => {
  const body = await request_body_sent_by((client) =>
    client.enroll_begin_piv("ATT", [], "SIG", "yubikey", null, "sparky-test", "Sparky"));
  assert.equal(body["display_name"], "Sparky");
  assert.equal(body["requested_handle"], "sparky-test");
});

test("a missing display_name is left out of the request", async () => {
  const body = await request_body_sent_by((client) => client.enroll_begin("EK", "AK"));
  assert.equal("display_name" in body, false);
});

test("enroll.ts passes display_name to every enrollment begin call", () => {
  const enroll_source_path = fileURLToPath(new URL("../../src/enroll.ts", import.meta.url));
  const enroll_source = fs.readFileSync(enroll_source_path, "utf8");
  const begin_calls = [...enroll_source.matchAll(/api_client\.(enroll_begin(?:_piv|_enclave)?)\(([\s\S]*?)\);/g)];
  assert.deepEqual(begin_calls.map((call) => call[1]).sort(), ["enroll_begin", "enroll_begin_enclave", "enroll_begin_piv"]);
  for (const [, method_name, argument_list] of begin_calls) {
    assert.match(argument_list as string, /\bdisplay_name\b/, `${method_name} is called without display_name`);
  }
});
