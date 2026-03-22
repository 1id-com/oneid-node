/**
 * Unit tests for the attestation module (DKIM canonicalization + RFC nonce).
 *
 * Pure function tests -- no network calls, no credential files.
 * Uses Node.js built-in test runner (node --test).
 */

import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";

import {
  canonicalise_header_value_using_dkim_relaxed,
  canonicalise_header_name_using_dkim_relaxed,
  canonicalise_headers_for_message_binding,
  canonicalise_body_using_dkim_simple,
  compute_rfc_message_binding_nonce,
} from "../attestation.js";

const _SAMPLE_EMAIL_HEADERS: Record<string, string> = {
  "From": "agent@mailpal.com",
  "To": "bob@example.com",
  "Subject": "Test Subject",
  "Date": "Thu, 19 Mar 2026 12:00:00 +0000",
  "Message-ID": "<test-001@mailpal.com>",
};

describe("DKIM relaxed header name canonicalization (RFC 6376 Section 3.4.2)", () => {
  it("lowercases header names", () => {
    assert.equal(canonicalise_header_name_using_dkim_relaxed("From"), "from");
    assert.equal(canonicalise_header_name_using_dkim_relaxed("MESSAGE-ID"), "message-id");
    assert.equal(canonicalise_header_name_using_dkim_relaxed("Content-Type"), "content-type");
  });

  it("strips leading and trailing whitespace from names", () => {
    assert.equal(canonicalise_header_name_using_dkim_relaxed("  Subject  "), "subject");
    assert.equal(canonicalise_header_name_using_dkim_relaxed("\tDate\t"), "date");
  });
});

describe("DKIM relaxed header value canonicalization (RFC 6376 Section 3.4.2)", () => {
  it("compresses interior whitespace runs to single space", () => {
    assert.equal(canonicalise_header_value_using_dkim_relaxed("hello   world"), "hello world");
    assert.equal(canonicalise_header_value_using_dkim_relaxed("a\t\tb"), "a b");
    assert.equal(canonicalise_header_value_using_dkim_relaxed("x  \t  y"), "x y");
  });

  it("strips trailing whitespace", () => {
    assert.equal(canonicalise_header_value_using_dkim_relaxed("value   "), "value");
    assert.equal(canonicalise_header_value_using_dkim_relaxed("value\t"), "value");
  });

  it("strips leading whitespace", () => {
    assert.equal(canonicalise_header_value_using_dkim_relaxed("   value"), "value");
  });

  it("unfolds CRLF-continuation lines", () => {
    assert.equal(
      canonicalise_header_value_using_dkim_relaxed("line1\r\n continuation"),
      "line1 continuation",
    );
  });

  it("unfolds LF-only continuation lines", () => {
    assert.equal(
      canonicalise_header_value_using_dkim_relaxed("line1\n continuation"),
      "line1 continuation",
    );
  });

  it("unfolds tab-continuation lines", () => {
    assert.equal(
      canonicalise_header_value_using_dkim_relaxed("line1\r\n\tcontinuation"),
      "line1 continuation",
    );
  });

  it("passes through simple values unchanged", () => {
    assert.equal(canonicalise_header_value_using_dkim_relaxed("simple"), "simple");
    assert.equal(canonicalise_header_value_using_dkim_relaxed("agent@mailpal.com"), "agent@mailpal.com");
  });
});

describe("DKIM simple body canonicalization (RFC 6376 Section 3.4.3)", () => {
  it("returns single CRLF for empty body", () => {
    assert.deepEqual(canonicalise_body_using_dkim_simple(Buffer.alloc(0)), Buffer.from("\r\n"));
  });

  it("strips trailing empty lines (multiple CRLF)", () => {
    assert.deepEqual(
      canonicalise_body_using_dkim_simple(Buffer.from("text\r\n\r\n\r\n")),
      Buffer.from("text\r\n"),
    );
  });

  it("appends CRLF if missing from non-empty body", () => {
    assert.deepEqual(
      canonicalise_body_using_dkim_simple(Buffer.from("text")),
      Buffer.from("text\r\n"),
    );
  });

  it("preserves body already ending with single CRLF", () => {
    assert.deepEqual(
      canonicalise_body_using_dkim_simple(Buffer.from("body text\r\n")),
      Buffer.from("body text\r\n"),
    );
  });

  it("preserves interior empty lines while stripping only trailing ones", () => {
    const input = Buffer.from("line1\r\n\r\nline3\r\n\r\n\r\n");
    const expected = Buffer.from("line1\r\n\r\nline3\r\n");
    assert.deepEqual(canonicalise_body_using_dkim_simple(input), expected);
  });
});

describe("canonicalise_headers_for_message_binding", () => {
  it("throws when required headers are missing", () => {
    assert.throws(
      () => canonicalise_headers_for_message_binding({ "From": "a@b.com" }),
      { message: /Missing required email header/ },
    );
  });

  it("produces a Buffer with all required headers", () => {
    const result = canonicalise_headers_for_message_binding(_SAMPLE_EMAIL_HEADERS);
    assert.ok(Buffer.isBuffer(result));
    const decoded = result.toString("utf-8");
    assert.ok(decoded.includes("from:agent@mailpal.com\r\n"));
    assert.ok(decoded.includes("to:bob@example.com\r\n"));
    assert.ok(decoded.includes("subject:Test Subject\r\n"));
    assert.ok(decoded.includes("date:Thu, 19 Mar 2026 12:00:00 +0000\r\n"));
    assert.ok(decoded.includes("message-id:<test-001@mailpal.com>\r\n"));
  });

  it("appends Hardware-Trust-Proof as last header without trailing CRLF", () => {
    const result = canonicalise_headers_for_message_binding(_SAMPLE_EMAIL_HEADERS);
    const decoded = result.toString("utf-8");
    assert.ok(decoded.endsWith("hardware-trust-proof:"));
    assert.ok(!decoded.endsWith("hardware-trust-proof:\r\n"));
  });

  it("includes a placeholder value for Hardware-Trust-Proof when provided", () => {
    const result = canonicalise_headers_for_message_binding(
      _SAMPLE_EMAIL_HEADERS,
      "placeholder-jwt-value",
    );
    const decoded = result.toString("utf-8");
    assert.ok(decoded.endsWith("hardware-trust-proof:placeholder-jwt-value"));
  });

  it("excludes Hardware-Trust-Proof from input headers (it is always appended last)", () => {
    const headers_with_htp = {
      ..._SAMPLE_EMAIL_HEADERS,
      "Hardware-Trust-Proof": "should-be-excluded-from-sorted-section",
    };
    const result = canonicalise_headers_for_message_binding(headers_with_htp);
    const decoded = result.toString("utf-8");
    const htp_occurrences = decoded.split("hardware-trust-proof:").length - 1;
    assert.equal(htp_occurrences, 1, "Hardware-Trust-Proof should appear exactly once (appended)");
  });

  it("sorts extra headers alphabetically after the required five", () => {
    const headers_with_extras = {
      ..._SAMPLE_EMAIL_HEADERS,
      "X-Zebra": "last-extra",
      "X-Alpha": "first-extra",
    };
    const result = canonicalise_headers_for_message_binding(headers_with_extras);
    const decoded = result.toString("utf-8");
    const alpha_position = decoded.indexOf("x-alpha:");
    const zebra_position = decoded.indexOf("x-zebra:");
    assert.ok(alpha_position < zebra_position, "x-alpha should come before x-zebra");
    const htp_position = decoded.indexOf("hardware-trust-proof:");
    assert.ok(zebra_position < htp_position, "extras should come before hardware-trust-proof");
  });

  it("is case-insensitive for input header keys", () => {
    const mixed_case_headers: Record<string, string> = {
      "FROM": "agent@mailpal.com",
      "to": "bob@example.com",
      "Subject": "Test Subject",
      "DATE": "Thu, 19 Mar 2026 12:00:00 +0000",
      "message-id": "<test-001@mailpal.com>",
    };
    const result_mixed = canonicalise_headers_for_message_binding(mixed_case_headers);
    const result_original = canonicalise_headers_for_message_binding(_SAMPLE_EMAIL_HEADERS);
    assert.deepEqual(result_mixed, result_original);
  });
});

describe("compute_rfc_message_binding_nonce (RFC Section 5.3)", () => {
  it("produces a base64url string without padding", () => {
    const nonce = compute_rfc_message_binding_nonce(
      _SAMPLE_EMAIL_HEADERS,
      Buffer.from("Hello, world!\r\n"),
      1711022400,
    );
    assert.equal(typeof nonce, "string");
    assert.ok(!nonce.includes("="), "no padding");
    assert.ok(!nonce.includes("+"), "no + (base64url uses - instead)");
    assert.ok(!nonce.includes("/"), "no / (base64url uses _ instead)");
  });

  it("produces exactly 43 characters (base64url of SHA-256)", () => {
    const nonce = compute_rfc_message_binding_nonce(
      _SAMPLE_EMAIL_HEADERS,
      Buffer.from("test body"),
      1711022400,
    );
    assert.equal(nonce.length, 43);
  });

  it("is deterministic for identical inputs", () => {
    const nonce_first = compute_rfc_message_binding_nonce(
      _SAMPLE_EMAIL_HEADERS,
      Buffer.from("Same body"),
      1711022400,
    );
    const nonce_second = compute_rfc_message_binding_nonce(
      _SAMPLE_EMAIL_HEADERS,
      Buffer.from("Same body"),
      1711022400,
    );
    assert.equal(nonce_first, nonce_second);
  });

  it("differs when body changes", () => {
    const nonce_a = compute_rfc_message_binding_nonce(
      _SAMPLE_EMAIL_HEADERS,
      Buffer.from("Body A"),
      1711022400,
    );
    const nonce_b = compute_rfc_message_binding_nonce(
      _SAMPLE_EMAIL_HEADERS,
      Buffer.from("Body B"),
      1711022400,
    );
    assert.notEqual(nonce_a, nonce_b);
  });

  it("differs when headers change", () => {
    const headers_a = { ..._SAMPLE_EMAIL_HEADERS, Subject: "Subject A" };
    const headers_b = { ..._SAMPLE_EMAIL_HEADERS, Subject: "Subject B" };
    const nonce_a = compute_rfc_message_binding_nonce(headers_a, Buffer.from("Same body"), 1711022400);
    const nonce_b = compute_rfc_message_binding_nonce(headers_b, Buffer.from("Same body"), 1711022400);
    assert.notEqual(nonce_a, nonce_b);
  });

  it("differs when timestamp changes", () => {
    const nonce_a = compute_rfc_message_binding_nonce(
      _SAMPLE_EMAIL_HEADERS,
      Buffer.from("Same body"),
      1711022400,
    );
    const nonce_b = compute_rfc_message_binding_nonce(
      _SAMPLE_EMAIL_HEADERS,
      Buffer.from("Same body"),
      1711022401,
    );
    assert.notEqual(nonce_a, nonce_b);
  });

  it("matches manual RFC Section 5.3 computation", () => {
    const body_bytes = Buffer.from("Hello, world!\r\n");
    const iat = 1711022400;

    const canonicalised_header_bytes = canonicalise_headers_for_message_binding(_SAMPLE_EMAIL_HEADERS);
    const h_hash = createHash("sha256").update(canonicalised_header_bytes).digest();

    const canonicalised_body = canonicalise_body_using_dkim_simple(body_bytes);
    const bh_raw = createHash("sha256").update(canonicalised_body).digest();

    const ts_bytes = Buffer.alloc(8);
    ts_bytes.writeBigUInt64BE(BigInt(iat));

    const message_binding = Buffer.concat([h_hash, bh_raw, ts_bytes]);
    const expected_nonce = createHash("sha256").update(message_binding).digest().toString("base64url");

    const actual_nonce = compute_rfc_message_binding_nonce(
      _SAMPLE_EMAIL_HEADERS,
      body_bytes,
      iat,
    );
    assert.equal(actual_nonce, expected_nonce);
  });

  it("handles large timestamps (year 2100+)", () => {
    const far_future_iat = 4102444800;
    const nonce = compute_rfc_message_binding_nonce(
      _SAMPLE_EMAIL_HEADERS,
      Buffer.from("future body"),
      far_future_iat,
    );
    assert.equal(nonce.length, 43);
    assert.equal(typeof nonce, "string");
  });

  it("handles zero timestamp", () => {
    const nonce = compute_rfc_message_binding_nonce(
      _SAMPLE_EMAIL_HEADERS,
      Buffer.from("epoch body"),
      0,
    );
    assert.equal(nonce.length, 43);
  });

  it("handles unicode body content", () => {
    const nonce = compute_rfc_message_binding_nonce(
      _SAMPLE_EMAIL_HEADERS,
      Buffer.from("Hello \u{1F600} world \u00E9\u00E8\u00EA"),
      1711022400,
    );
    assert.equal(nonce.length, 43);
  });
});

