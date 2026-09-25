/**
 * AUD-F07: a downloaded helper is installed only after its SHA-256 checksum AND
 * (Windows/macOS) the publisher's code signature verify; a checksum that cannot
 * be fetched refuses the install. OWN-030: the Secure Enclave helper is fetched
 * the same way (macOS only). Mirrors oneid-sdk tests/test_helper_download_is_verified_or_refused.py.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import type { AddressInfo } from "node:net";

import {
  download_binary_from_github_release,
  ensure_secure_enclave_helper_available,
  verify_publisher_code_signature_of_downloaded_release_asset,
} from "../helper.js";
import { BinaryNotFoundError, NoHSMError } from "../exceptions.js";

async function with_release_server(
  files: Record<string, Buffer | null>,
  run: (url_template: string) => Promise<void>,
): Promise<void> {
  const server = http.createServer((request, response) => {
    const name = decodeURIComponent((request.url ?? "").split("/").pop() ?? "");
    const body = files[name];
    if (body == null) { response.writeHead(404); response.end(); return; }
    response.writeHead(200); response.end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  try {
    await run(`http://127.0.0.1:${port}/{binary_name}`);
  } finally {
    server.close();
  }
}

function fresh_directory(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "oneid-helper-test-"));
}

test("a checksum that cannot be downloaded refuses the install", async () => {
  const directory = fresh_directory();
  const destination = path.join(directory, "oneid-enroll-test");
  await with_release_server({ "oneid-enroll-test": Buffer.alloc(200_000, 120), "oneid-enroll-test.sha256": null }, async (template) => {
    await assert.rejects(download_binary_from_github_release("oneid-enroll-test", destination, template), BinaryNotFoundError);
  });
  assert.equal(fs.existsSync(destination), false);
  assert.deepEqual(fs.readdirSync(directory), []);
});

test("a checksum mismatch refuses the install", async () => {
  const directory = fresh_directory();
  const destination = path.join(directory, "oneid-enroll-test");
  await with_release_server({
    "oneid-enroll-test": Buffer.alloc(200_000, 120),
    "oneid-enroll-test.sha256": Buffer.from("0".repeat(64) + "  oneid-enroll-test\n"),
  }, async (template) => {
    await assert.rejects(download_binary_from_github_release("oneid-enroll-test", destination, template), /checksum mismatch/);
  });
  assert.equal(fs.existsSync(destination), false);
});

test("a matching checksum still requires the publisher signature (Windows/macOS)", { skip: os.platform() === "linux" }, async () => {
  const directory = fresh_directory();
  const destination = path.join(directory, "oneid-enroll-test");
  const content = Buffer.alloc(200_000, 120);
  const sha256 = crypto.createHash("sha256").update(content).digest("hex");
  await with_release_server({
    "oneid-enroll-test": content,
    "oneid-enroll-test.sha256": Buffer.from(`${sha256}  oneid-enroll-test\n`),
  }, async (template) => {
    await assert.rejects(download_binary_from_github_release("oneid-enroll-test", destination, template), /not validly signed/);
  });
  assert.equal(fs.existsSync(destination), false);
});

test("an unsigned file fails the Authenticode check", { skip: os.platform() !== "win32" }, () => {
  const unsigned_file = path.join(fresh_directory(), "unsigned-helper.exe");
  fs.writeFileSync(unsigned_file, Buffer.concat([Buffer.from("MZ"), crypto.randomBytes(4096)]));
  assert.throws(() => verify_publisher_code_signature_of_downloaded_release_asset(unsigned_file, "unsigned-helper.exe"), /not validly signed/);
});

test("the published signed helper passes the Authenticode check", { skip: os.platform() !== "win32" }, (context) => {
  const cached_helper = path.join(process.env.APPDATA ?? "", "oneid", "bin", "oneid-enroll-windows-amd64.exe");
  if (!fs.existsSync(cached_helper)) { context.skip("no published helper cached on this machine"); return; }
  verify_publisher_code_signature_of_downloaded_release_asset(cached_helper, path.basename(cached_helper));
});

test("the Secure Enclave helper exists only on macOS", { skip: os.platform() === "darwin" }, async () => {
  await assert.rejects(ensure_secure_enclave_helper_available(), NoHSMError);
});
