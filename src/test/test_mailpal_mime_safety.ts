/**
 * Node mail building matches what Python's email package does for the Python SDK:
 * AUD-F84 no CR/LF injection, AUD-F85 RFC 2047 for non-ASCII Subject/display
 * names, AUD-F75 honest Content-Transfer-Encoding, AUD-F29 SMTP dot-stuffing.
 * Mirrors oneid-sdk tests/test_mailpal_mime_safety.py.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { send, prepare_message_bytes_for_smtp_data_transmission, reject_header_injection_in_caller_supplied_value } from "../mailpal.js";
import { save_credentials, type StoredCredentials } from "../credentials.js";

const isolated_config_directory = fs.mkdtempSync(path.join(os.tmpdir(), "oneid-node-test-config-"));
process.env["APPDATA"] = isolated_config_directory;
process.env["XDG_CONFIG_HOME"] = isolated_config_directory;
save_credentials({
  client_id: "id-tstmm-aaaaa-bbbbb-ccccc", client_secret: "", token_endpoint: "http://127.0.0.1:9/token",
  api_base_url: "http://127.0.0.1:9", trust_tier: "declared", key_algorithm: "ecdsa-p256",
  private_key_pem: crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  mailpal_email: "id-tstmm-aaaaa-bbbbb-ccccc@mailpal.com",
} as StoredCredentials);

async function build_without_attestation(overrides: Record<string, unknown>): Promise<string> {
  const result = await send({ to: ["r@example.com"], subject: "Plain", text_body: "Body", attestation_mode: "none", deliver: false, ...overrides } as never);
  return (result.rfc5322_message_bytes as Buffer).toString("utf-8");
}

test("CR or LF in any header input is refused (AUD-F84)", async () => {
  await assert.rejects(build_without_attestation({ subject: "Hi\r\nBcc: victim@example.com" }), /header injection refused/);
  await assert.rejects(build_without_attestation({ to: ["r@example.com\r\nRCPT TO:<x@example.com>"] }), /header injection refused/);
  await assert.rejects(build_without_attestation({ reply_to: "a@example.com\nX-Evil: 1" }), /header injection refused/);
  assert.throws(() => reject_header_injection_in_caller_supplied_value("x", "a\rb"), /header injection refused/);
});

test("non-ASCII Subject and display names are RFC 2047 encoded in short encoded-words (AUD-F85)", async () => {
  const long_subject = "Grüße aus Zürich – ".repeat(6);
  const message = await build_without_attestation({ subject: long_subject, to: ["Zoë Ünicode <r@example.com>"] });
  const header_section = message.slice(0, message.indexOf("\r\n\r\n"));
  assert.ok(/^[\x00-\x7f]*$/.test(header_section), "headers must be ASCII on the wire");
  for (const encoded_word of header_section.match(/=\?utf-8\?b\?[^?]*\?=/g) ?? []) {
    assert.ok(encoded_word.length <= 75, `encoded-word too long: ${encoded_word.length}`);
  }
  const subject_line = header_section.split("\r\n").findIndex((line) => line.startsWith("Subject:"));
  assert.ok(subject_line >= 0);
  assert.match(header_section, /To: =\?utf-8\?b\?[^?]+\?= <r@example\.com>/);
});

test("non-ASCII addresses and message ids are refused (no SMTPUTF8)", async () => {
  await assert.rejects(build_without_attestation({ to: ["zoë@example.com"] }), /must be ASCII/);
  await assert.rejects(build_without_attestation({ in_reply_to: "<ü@example.com>" }), /must be ASCII/);
});

test("text bodies are quoted-printable with CRLF line ends, as the Python SDK forces (AUD-F75)", async () => {
  const ascii_message = await build_without_attestation({ text_body: "line one\nline two" });
  assert.match(ascii_message, /Content-Transfer-Encoding: quoted-printable/);
  assert.ok(ascii_message.includes("line one\r\nline two"));
  const utf8_message = await build_without_attestation({ text_body: "héllo wörld" });
  assert.ok(utf8_message.includes("h=C3=A9llo w=C3=B6rld"));
  const long_line_message = await build_without_attestation({ text_body: "x".repeat(200) + " \nend" });
  const body = long_line_message.slice(long_line_message.indexOf("\r\n\r\n") + 4);
  for (const line of body.split("\r\n")) { assert.ok(line.length <= 76, `QP line too long: ${line.length}`); }
  assert.ok(body.includes("=20\r\nend") || body.includes(" =\r\n"), "trailing space before a hard break is encoded");
  assert.equal(body.replace(/=\r\n/g, "").split("\r\n")[0].replace(/=20$/, " "), "x".repeat(200) + " ");
});

test("SMTP DATA is dot-stuffed and terminated like smtplib (AUD-F29)", () => {
  const stuffed = prepare_message_bytes_for_smtp_data_transmission(Buffer.from(".first\r\nmiddle\r\n.\r\n..two\r\nlast\r\n", "latin1")).toString("latin1");
  assert.equal(stuffed, "..first\r\nmiddle\r\n..\r\n...two\r\nlast\r\n.\r\n");
  const unterminated = prepare_message_bytes_for_smtp_data_transmission(Buffer.from("no final newline", "latin1")).toString("latin1");
  assert.equal(unterminated, "no final newline\r\n.\r\n");
  const utf8_bytes = Buffer.from("Grüße\r\n", "utf-8");
  assert.deepEqual(prepare_message_bytes_for_smtp_data_transmission(utf8_bytes).subarray(0, utf8_bytes.length), utf8_bytes);
});
