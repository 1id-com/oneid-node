/**
 * Go binary helper for the 1id.com Node.js SDK.
 *
 * Manages the oneid-enroll Go binary:
 * - Locates the binary (cached or PATH)
 * - Downloads it from GitHub releases if not present
 * - Spawns it for HSM operations (detect, extract, activate, sign)
 * - Parses JSON output
 *
 * The binary handles all platform-specific HSM operations:
 * - TPM access (Windows TBS.dll, Linux /dev/tpm*)
 * - YubiKey/PIV access (PCSC)
 * - Privilege elevation (UAC, sudo, pkexec)
 */

import { SDK_USER_AGENT } from "./version.js";
import * as child_process from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as https from "node:https";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";

import {
  BinaryNotFoundError,
  HSMAccessError,
  NoHSMError,
  TPMSetupRequiredError,
  UACDeniedError,
} from "./exceptions.js";

// -- GitHub release URL for auto-download --
const GITHUB_RELEASE_DOWNLOAD_URL_TEMPLATE =
  "https://github.com/1id-com/oneid-enroll/releases/latest/download/{binary_name}";

// -- Binary naming convention --
const BINARY_NAME_PREFIX = "oneid-enroll";

/**
 * Return the platform-specific binary filename.
 */
function get_platform_binary_name(): string {
  const system = os.platform();
  let machine: string = os.arch();

  if (machine === "x64") { machine = "amd64"; }
  else if (machine === "arm64") { /* already correct */ }

  if (system === "win32") {
    return `${BINARY_NAME_PREFIX}-windows-${machine}.exe`;
  } else if (system === "darwin") {
    return `${BINARY_NAME_PREFIX}-darwin-${machine}`;
  } else {
    return `${BINARY_NAME_PREFIX}-linux-${machine}`;
  }
}

/**
 * Return the directory where downloaded binaries are cached.
 */
function get_binary_cache_directory(): string {
  if (os.platform() === "win32") {
    const base = process.env["APPDATA"] ?? path.join(os.homedir(), "AppData", "Roaming");
    return path.join(base, "oneid", "bin");
  } else {
    return path.join(os.homedir(), ".local", "share", "oneid", "bin");
  }
}

/**
 * Check if a file exists and is executable.
 */
function file_exists_and_is_executable(file_path: string): boolean {
  try {
    fs.accessSync(file_path, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Locate the oneid-enroll binary.
 *
 * Search order:
 * 1. Binary cache directory (~/.local/share/oneid/bin/ or %APPDATA%/oneid/bin/)
 * 2. Current working directory
 * 3. System PATH
 *
 * @returns Path to the binary if found, null otherwise.
 */
export function find_binary(): string | null {
  const binary_name = get_platform_binary_name();

  // 1. Check cache directory
  const cache_dir = get_binary_cache_directory();
  const cached_binary_path = path.join(cache_dir, binary_name);
  if (file_exists_and_is_executable(cached_binary_path)) {
    return cached_binary_path;
  }

  // 2. Check current working directory
  const local_binary_path = path.join(process.cwd(), binary_name);
  if (file_exists_and_is_executable(local_binary_path)) {
    return local_binary_path;
  }

  // Also check generic name
  const generic_name = os.platform() === "win32" ? `${BINARY_NAME_PREFIX}.exe` : BINARY_NAME_PREFIX;
  const local_generic_path = path.join(process.cwd(), generic_name);
  if (file_exists_and_is_executable(local_generic_path)) {
    return local_generic_path;
  }

  // 3. Check PATH
  const which_command = os.platform() === "win32" ? "where" : "which";
  for (const name_to_search of [binary_name, generic_name]) {
    try {
      const result = child_process.execSync(`${which_command} ${name_to_search}`, {
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "pipe"],
      });
      const found_path = result.trim().split("\n")[0]?.trim();
      if (found_path && fs.existsSync(found_path)) {
        return found_path;
      }
    } catch {
      // Not found in PATH
    }
  }

  return null;
}

/**
 * Download a file from a URL to a local path. Follows redirects (up to 5).
 */
function download_file_to_path(url: string, destination: string, max_redirects: number = 5): Promise<void> {
  return new Promise((resolve, reject) => {
    if (max_redirects <= 0) {
      reject(new BinaryNotFoundError("Too many redirects while downloading binary"));
      return;
    }

    const transport = url.startsWith("https:") ? https : http;
    transport.get(url, { headers: { "User-Agent": SDK_USER_AGENT } }, (res) => {
      // Handle redirects (GitHub releases redirect to S3)
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        download_file_to_path(res.headers.location, destination, max_redirects - 1)
          .then(resolve)
          .catch(reject);
        return;
      }

      if (res.statusCode !== 200) {
        reject(new BinaryNotFoundError(
          `Failed to download from ${url}: HTTP ${res.statusCode}`
        ));
        return;
      }

      const file_stream = fs.createWriteStream(destination);
      res.pipe(file_stream);
      file_stream.on("finish", () => {
        file_stream.close();
        resolve();
      });
      file_stream.on("error", (err) => {
        reject(new BinaryNotFoundError(`Failed to write binary to ${destination}: ${err.message}`));
      });
    }).on("error", (err) => {
      reject(new BinaryNotFoundError(`Failed to download from ${url}: ${err.message}`));
    });
  });
}

/**
 * Download the content of a URL as a string. Follows redirects.
 */
function download_text_from_url(url: string, max_redirects: number = 5): Promise<string> {
  return new Promise((resolve, reject) => {
    if (max_redirects <= 0) {
      reject(new Error("Too many redirects"));
      return;
    }

    const transport = url.startsWith("https:") ? https : http;
    transport.get(url, { headers: { "User-Agent": SDK_USER_AGENT } }, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        download_text_from_url(res.headers.location, max_redirects - 1)
          .then(resolve)
          .catch(reject);
        return;
      }

      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }

      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => { chunks.push(chunk); });
      res.on("end", () => { resolve(Buffer.concat(chunks).toString("utf-8")); });
    }).on("error", reject);
  });
}

/**
 * Download the oneid-enroll binary from the GitHub 'latest' release.
 *
 * Downloads to a temporary file first, verifies the SHA-256 checksum,
 * then moves to the final location.
 */
async function download_binary_from_github_release(
  binary_name: string,
  destination_path: string,
): Promise<string> {
  const binary_download_url = GITHUB_RELEASE_DOWNLOAD_URL_TEMPLATE.replace("{binary_name}", binary_name);
  const checksum_download_url = GITHUB_RELEASE_DOWNLOAD_URL_TEMPLATE.replace("{binary_name}", binary_name + ".sha256");

  const destination_dir = path.dirname(destination_path);
  fs.mkdirSync(destination_dir, { recursive: true });

  // Use a temp file for atomic download
  const temp_file_path = path.join(destination_dir, `oneid-enroll-download-${Date.now()}.tmp`);

  try {
    // Step 1: Download binary
    await download_file_to_path(binary_download_url, temp_file_path);
    const downloaded_size = fs.statSync(temp_file_path).size;

    if (downloaded_size < 100_000) {
      throw new BinaryNotFoundError(
        `Downloaded binary is suspiciously small (${downloaded_size} bytes). ` +
        "The download URL may be incorrect or the release may be empty."
      );
    }

    // Step 2: Verify SHA-256 checksum
    try {
      const checksum_text = await download_text_from_url(checksum_download_url);
      const expected_sha256_hash = checksum_text.trim().split(/\s+/)[0]?.toLowerCase();

      const file_buffer = fs.readFileSync(temp_file_path);
      const actual_sha256_hash = crypto.createHash("sha256").update(file_buffer).digest("hex").toLowerCase();

      if (actual_sha256_hash !== expected_sha256_hash) {
        throw new BinaryNotFoundError(
          `SHA-256 checksum mismatch for ${binary_name}. ` +
          `Expected: ${expected_sha256_hash}, got: ${actual_sha256_hash}. ` +
          "The binary may have been tampered with or the download was corrupted."
        );
      }
    } catch (checksum_error) {
      if (checksum_error instanceof BinaryNotFoundError) { throw checksum_error; }
      // Checksum download failed -- proceed without verification (warn)
      console.warn(
        `[oneid] Could not download checksum file (${checksum_error}). ` +
        "Proceeding without verification."
      );
    }

    // Step 3: Move temp file to final destination
    if (fs.existsSync(destination_path)) {
      fs.unlinkSync(destination_path);
    }
    fs.renameSync(temp_file_path, destination_path);

    // Step 4: Set executable permission on non-Windows
    if (os.platform() !== "win32") {
      fs.chmodSync(destination_path, 0o755);
    }

    return destination_path;
  } finally {
    // Clean up temp file on failure
    try {
      if (fs.existsSync(temp_file_path)) { fs.unlinkSync(temp_file_path); }
    } catch { /* best effort */ }
  }
}

/**
 * Ensure the oneid-enroll binary is available, downloading if needed.
 *
 * @returns Path to the available binary.
 * @throws BinaryNotFoundError if the binary cannot be found or downloaded.
 */
/**
 * 2.2.0: `sign` hashes inputs over 1024 bytes with a TPM hash sequence, which every
 * sender-constrained request (RFC 9421 signature base, OWN-038) needs; 2.1.0 was the
 * corrected enrollment proof (review 072 #1).
 */
export const MINIMUM_ONEID_ENROLL_HELPER_VERSION: [number, number, number] = [2, 2, 0];
const helper_versions_already_checked = new Map<string, boolean>();

export function parse_version_triple(version_text: unknown): [number, number, number] {
  const parts = String(version_text ?? "").trim().replace(/^v/, "").split(".").slice(0, 3).map(Number);
  if (parts.length !== 3 || parts.some((part) => !Number.isInteger(part))) { return [0, 0, 0]; }
  return [parts[0], parts[1], parts[2]];
}

function version_triple_at_least(version: [number, number, number], minimum: [number, number, number]): boolean {
  for (let index = 0; index < 3; index++) {
    if (version[index] !== minimum[index]) { return version[index] > minimum[index]; }
  }
  return true;
}

/** OWN-026: run `oneid-enroll version --json` once per (path, mtime); a helper
 * older than MINIMUM_ONEID_ENROLL_HELPER_VERSION must not be used. */
export function helper_binary_meets_minimum_version(binary_path: string): boolean {
  let cache_key: string;
  try {
    cache_key = `${binary_path}|${fs.statSync(binary_path).mtimeMs}`;
  } catch {
    return false;
  }
  if (!helper_versions_already_checked.has(cache_key)) {
    let reported_version: unknown = null;
    try {
      const stdout = child_process.execFileSync(binary_path, ["version", "--json"], { encoding: "utf8", timeout: 15000 });
      reported_version = JSON.parse(stdout.slice(stdout.indexOf("{"))).version;
    } catch { reported_version = null; }
    helper_versions_already_checked.set(cache_key,
      version_triple_at_least(parse_version_triple(reported_version), MINIMUM_ONEID_ENROLL_HELPER_VERSION));
  }
  return helper_versions_already_checked.get(cache_key) === true;
}

export async function ensure_binary_available(): Promise<string> {
  const found_binary_path = find_binary();
  if (found_binary_path != null && helper_binary_meets_minimum_version(found_binary_path)) {
    return found_binary_path;
  }
  // Missing or older than the minimum: download the current release into the
  // cache (replacing a stale cached copy).

  // Binary not found locally -- attempt auto-download
  const binary_name = get_platform_binary_name();
  const cache_dir = get_binary_cache_directory();
  const destination = path.join(cache_dir, binary_name);

  try {
    return await download_binary_from_github_release(binary_name, destination);
  } catch (download_error) {
    throw new BinaryNotFoundError(
      `oneid-enroll binary not found in cache, current directory, or PATH, ` +
      `and auto-download failed: ${download_error}. ` +
      `Expected filename: ${binary_name}. ` +
      `Manual download: https://github.com/1id-com/oneid-enroll/releases/latest`
    );
  }
}

/**
 * Run an oneid-enroll subcommand and parse its JSON output.
 */
export async function run_binary_command(
  command: string,
  args?: string[],
  json_mode: boolean = true,
  timeout_milliseconds: number = 30_000,
): Promise<Record<string, unknown>> {
  const binary_path = await ensure_binary_available();

  const cmd_args = [command];
  if (json_mode) { cmd_args.push("--json"); }
  if (args) { cmd_args.push(...args); }

  return new Promise((resolve, reject) => {
    let stdout_data = "";
    let stderr_data = "";

    const spawned_process = child_process.spawn(binary_path, cmd_args, {
      stdio: ["pipe", "pipe", "pipe"],
      timeout: timeout_milliseconds,
    });

    spawned_process.stdout?.on("data", (chunk: Buffer) => { stdout_data += chunk.toString(); });
    spawned_process.stderr?.on("data", (chunk: Buffer) => { stderr_data += chunk.toString(); });

    spawned_process.on("error", (err) => {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        reject(new BinaryNotFoundError(`Could not execute ${binary_path}: file not found`));
      } else if ((err as NodeJS.ErrnoException).code === "EACCES") {
        reject(new BinaryNotFoundError(`Could not execute ${binary_path}: permission denied`));
      } else {
        reject(new HSMAccessError(`Error spawning ${binary_path}: ${err.message}`));
      }
    });

    spawned_process.on("close", (exit_code) => {
      let output: Record<string, unknown>;

      if (json_mode && stdout_data.trim()) {
        try {
          output = JSON.parse(stdout_data.trim());
        } catch {
          reject(new HSMAccessError(
            `oneid-enroll returned invalid JSON: ${stdout_data.slice(0, 500)}`
          ));
          return;
        }
      } else {
        output = { stdout: stdout_data, stderr: stderr_data, returncode: exit_code };
      }

      if (exit_code !== 0) {
        const error_code = (output.error_code as string) ?? "UNKNOWN";
        const error_message = (output.error as string) ?? (stderr_data.trim() || `Exit code ${exit_code}`);

        if (error_code === "TBS_ACCESS_DENIED" || error_code === "TBS_ACCESS_NOT_CONFIGURED") {
          reject(new TPMSetupRequiredError(error_message));
        } else if (error_code === "NO_HSM_FOUND" || /no.*hsm/i.test(error_message) || /no.*tpm/i.test(error_message)) {
          reject(new NoHSMError(error_message));
        } else if (error_code === "UAC_DENIED" || /denied/i.test(error_message)) {
          reject(new UACDeniedError(error_message));
        } else if (error_code === "HSM_ACCESS_ERROR") {
          reject(new HSMAccessError(error_message));
        } else {
          reject(new HSMAccessError(`oneid-enroll '${command}' failed: ${error_message}`));
        }
        return;
      }

      resolve(output);
    });
  });
}

/**
 * Detect available hardware security modules via the Go binary.
 *
 * Runs 'oneid-enroll detect --json' which does NOT require elevation.
 */
// CROSS_IMPL_SYNC: hsm_detect
// Implementations: py:oneid/helper.py go:internal/piv/detect.go+tpm/detect.go node:src/helper.ts
export async function detect_available_hsms(): Promise<Record<string, unknown>[]> {
  try {
    const output = await run_binary_command("detect");
    return (output.hsms as Record<string, unknown>[]) ?? [];
  } catch (error) {
    if (error instanceof NoHSMError) { return []; }
    if (error instanceof BinaryNotFoundError) { throw error; }
    return [];
  }
}

/**
 * Signing capability tier for a specific HSM type.
 *
 * Tier A: Go binary (oneid-enroll) available -- handles all HSM types.
 * Tier B: Native extension available (pcsclite for PIV) -- no subprocess needed.
 * Tier C: Software-only -- no hardware signing possible.
 */
export interface SigningCapabilityTierDetectionResult {
  tier_a_go_binary_is_available: boolean;
  tier_a_go_binary_version: string | null;
  tier_a_go_binary_path: string | null;
  tier_b_piv_via_pcsclite_is_available: boolean;
  tier_c_software_only_is_available: boolean;
  recommended_piv_tier: "A" | "B" | "C";
  recommended_tpm_tier: "A" | "C";
}

// CROSS_IMPL_SYNC: tier_detect
// Implementations: py:oneid/helper.py node:src/helper.ts
/**
 * Detect which signing capability tiers are available on this system.
 *
 * The 1id SDK supports three tiers of hardware signing:
 *
 * Tier A -- Go binary (oneid-enroll):
 *   Handles all HSM types (TPM, PIV, Enclave). Requires the compiled binary.
 *   Supports --serial/--reader for multi-YubiKey targeting (v1.3.0+).
 *
 * Tier B -- Native Node.js extensions (pcsclite for PIV):
 *   Direct PC/SC access without spawning a subprocess. Requires the
 *   'pcsclite' or '@nickcis/smartcard' npm package (native C++ addon).
 *   Currently PIV-only. Not yet implemented -- detection is a placeholder
 *   that checks whether the pcsclite module can be loaded.
 *
 * Tier C -- Software-only:
 *   No hardware signing. Always available as baseline.
 */
export async function detect_available_signing_capability_tiers(): Promise<SigningCapabilityTierDetectionResult> {
  const result: SigningCapabilityTierDetectionResult = {
    tier_a_go_binary_is_available: false,
    tier_a_go_binary_version: null,
    tier_a_go_binary_path: null,
    tier_b_piv_via_pcsclite_is_available: false,
    tier_c_software_only_is_available: true,
    recommended_piv_tier: "C",
    recommended_tpm_tier: "C",
  };

  // Tier A: Go binary check
  try {
    const binary_path = find_binary();
    if (binary_path != null) {
      const version_output = await run_binary_command("version");
      result.tier_a_go_binary_is_available = true;
      result.tier_a_go_binary_version = (version_output.version as string) ?? null;
      result.tier_a_go_binary_path = binary_path;
      result.recommended_piv_tier = "A";
      result.recommended_tpm_tier = "A";
    }
  } catch {
    // Go binary not available or not working
  }

  // Tier B PIV: smartcard npm package check
  // The 'smartcard' package provides N-API PC/SC access from Node.js.
  // When available, it enables multi-YubiKey enumeration and targeted
  // PIV signing without the Go binary.
  if (is_tier_b_piv_via_smartcard_available()) {
    result.tier_b_piv_via_pcsclite_is_available = true;
    if (!result.tier_a_go_binary_is_available) {
      result.recommended_piv_tier = "B";
    }
  }

  return result;
}

/**
 * Extract attestation data from an HSM. Never elevates: EK/NV reads and
 * transient CreatePrimary work as an ordinary user (oneid-enroll >= 2.0.0).
 */
export async function extract_attestation_data(
  hsm: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const hsm_type = (hsm.type as string) ?? "tpm";
  return run_binary_command("extract", ["--type", hsm_type]);
}

/**
 * Enrollment co-residency proof that needs NO elevation (oneid-enroll >= 2.0.0):
 * import the Registrar-wrapped object under the EK, load it, and certify it
 * with the AK over the Registrar nonce. Windows allows these TPM commands to
 * ordinary users (ActivateCredential it does not).
 */
export async function import_and_certify_wrapped_object_with_tpm(
  wrapped_object_public_b64: string,
  wrapped_object_duplicate_b64: string,
  wrapped_object_in_sym_seed_b64: string,
  certify_nonce_b64: string,
): Promise<Record<string, unknown>> {
  return run_binary_command("import-certify", [
    "--wrapped-object-public", wrapped_object_public_b64,
    "--wrapped-object-duplicate", wrapped_object_duplicate_b64,
    "--wrapped-object-in-sym-seed", wrapped_object_in_sym_seed_b64,
    "--certify-nonce", certify_nonce_b64,
  ], false, 120_000);
}

/**
 * Decrypt a credential activation challenge via the HSM (requires elevation).
 */
export async function activate_credential(
  _hsm: Record<string, unknown>,
  credential_blob_b64: string,
  encrypted_secret_b64: string,
  ak_handle: string,
): Promise<string> {
  const activate_args = [
    "--elevated",
    "--credential-blob", credential_blob_b64,
    "--encrypted-secret", encrypted_secret_b64,
  ];
  if (ak_handle && ak_handle !== "transient") {
    activate_args.push("--ak-handle", ak_handle);
  }
  const output = await run_binary_command("activate", activate_args, true, 120_000);
  return (output.decrypted_credential as string) ?? "";
}

/**
 * Run the one-time TBS access setup via the Go binary.
 *
 * Calls 'oneid-enroll setup-tbs --elevated --json' which sets a Windows
 * registry key to allow non-admin users to access TPM Base Services.
 * Triggers a UAC prompt on Windows. No-op on other platforms.
 *
 * @returns Object with ok, already_set, and optionally platform fields.
 * @throws UACDeniedError if the user denied the UAC prompt.
 * @throws HSMAccessError if the registry key could not be set.
 */
export async function setup_tbs_for_non_admin_tpm_access(): Promise<Record<string, unknown>> {
  return run_binary_command("setup-tbs", ["--elevated"]);
}

/**
 * Sign a challenge nonce using the PIV key in slot 9a -- NO ELEVATION NEEDED.
 *
 * This is the core of PIV-backed challenge-response during enrollment.
 * The agent signs the server-provided nonce with the YubiKey's PIV slot 9a
 * key (ECDSA-SHA256), proving it controls the hardware that was attested.
 *
 * PIV slot 9a with pin-policy=NEVER means no human interaction required.
 *
 * Uses a tiered fallback strategy:
 *
 *   Tier A (Go binary): Spawns oneid-enroll with --serial/--reader targeting.
 *     Supports all platforms. v1.3.0+ supports multi-YubiKey by serial.
 *   Tier B (pcsclite): Direct PC/SC signing from Node.js without subprocess.
 *     Requires the pcsclite npm package (native C++ addon). NOT YET IMPLEMENTED.
 *   Tier C: Not applicable for PIV (hardware key is required).
 *
 * Currently uses Tier A exclusively. When pcsclite support is added, this
 * function will attempt Tier A first and fall back to Tier B if the Go binary
 * is unavailable.
 */
// CROSS_IMPL_SYNC: piv_sign
// Implementations: py:oneid/helper.py go:internal/piv/sign.go node:src/helper.ts
export async function sign_challenge_with_piv(
  nonce_b64: string,
  piv_serial_number?: number,
  piv_reader_name_substring?: string,
): Promise<Record<string, unknown>> {
  // Tier A: Go binary with optional --serial/--reader targeting
  const sign_args = [
    "--nonce", nonce_b64,
    "--type", "yubikey",
  ];
  if (piv_serial_number !== undefined) {
    sign_args.push("--serial", String(piv_serial_number));
  } else if (piv_reader_name_substring !== undefined) {
    sign_args.push("--reader", piv_reader_name_substring);
  }

  try {
    return await run_binary_command("sign", sign_args);
  } catch (tier_a_error: any) {
    // If Go binary is available but signing failed for a non-binary reason,
    // and Tier B isn't available, re-throw immediately
    if (!(tier_a_error instanceof BinaryNotFoundError)) {
      // Hardware error from Go binary -- try Tier B as fallback only if available
      if (!is_tier_b_piv_via_smartcard_available()) {
        throw tier_a_error;
      }
      // Tier A had a hardware error, try Tier B (different code path may succeed)
    }
  }

  // Tier B: smartcard npm package direct signing
  if (!is_tier_b_piv_via_smartcard_available()) {
    throw new BinaryNotFoundError(
      "oneid-enroll binary not found and the 'smartcard' npm package is not "
      + "installed for Tier B PIV signing. Install either the Go binary or "
      + "the smartcard package: npm install smartcard"
    );
  }

  // Enumerate and select target YubiKey
  const available_yubikeys = await enumerate_all_piv_capable_yubikeys_via_smartcard();

  if (available_yubikeys.length === 0) {
    throw new NoHSMError("No PIV-capable YubiKeys found via PC/SC (Tier B)");
  }

  const target_reader_name = select_preferred_piv_yubikey_reader_name(
    available_yubikeys,
    piv_serial_number,
  );
  if (target_reader_name == null) {
    throw new NoHSMError(
      piv_serial_number !== undefined
        ? `YubiKey with serial ${piv_serial_number} not found among ${available_yubikeys.length} connected key(s)`
        : `No suitable YubiKey could be selected from ${available_yubikeys.length} connected key(s)`,
    );
  }

  const nonce_bytes = Buffer.from(nonce_b64, "base64");
  return sign_nonce_with_specific_piv_reader_via_smartcard(nonce_bytes, target_reader_name);
}

/**
 * Sign a challenge nonce using the TPM AK -- NO ELEVATION NEEDED.
 *
 * This is the core of ongoing TPM-backed authentication.
 */
// CROSS_IMPL_SYNC: tpm_sign
// Implementations: py:oneid/helper.py go:internal/tpm/sign.go node:src/helper.ts
export async function sign_challenge_with_tpm(
  nonce_b64: string,
  ak_handle: string,
): Promise<Record<string, unknown>> {
  return run_binary_command("sign", [
    "--nonce", nonce_b64,
    "--ak-handle", ak_handle,
  ]);
}

const ENCLAVE_DEFAULT_KEY_TAG = "com.1id.enclave.default";
const SE_HELPER_COMMAND_TIMEOUT_MS = 15_000;
const CTKD_RESPAWN_WAIT_MS = 3_000;

function attempt_macos_cryptotokenkit_daemon_recovery(): boolean {
  if (os.platform() !== "darwin") { return false; }
  try {
    const pgrep_result = child_process.execFileSync(
      "pgrep", ["-u", String(process.getuid?.()), "-x", "ctkd"],
      { encoding: "utf-8", timeout: 5_000 },
    ).trim();
    if (!pgrep_result) { return false; }
    for (const ctkd_pid_string of pgrep_result.split("\n")) {
      const ctkd_pid = parseInt(ctkd_pid_string.trim(), 10);
      if (!isNaN(ctkd_pid)) {
        process.kill(ctkd_pid, "SIGKILL");
      }
    }
    child_process.execFileSync("sleep", [String(CTKD_RESPAWN_WAIT_MS / 1000)]);
    return true;
  } catch {
    return false;
  }
}

function find_secure_enclave_helper_binary(): string | null {
  const se_helper_name = "oneid-se-helper";

  const cache_dir = get_binary_cache_directory();
  const cached_path = path.join(cache_dir, se_helper_name);
  if (file_exists_and_is_executable(cached_path)) { return cached_path; }

  const main_binary = find_binary();
  if (main_binary != null) {
    const sibling_path = path.join(path.dirname(main_binary), se_helper_name);
    if (file_exists_and_is_executable(sibling_path)) { return sibling_path; }
  }

  const home_oneid_path = path.join(os.homedir(), ".oneid", "bin", se_helper_name);
  if (file_exists_and_is_executable(home_oneid_path)) { return home_oneid_path; }

  return null;
}

/**
 * Sign a challenge nonce using the Apple Secure Enclave -- NO ELEVATION NEEDED.
 *
 * Uses the oneid-se-helper Swift binary directly (NOT oneid-enroll, which
 * does not support enclave signing).
 * Only available on macOS with Apple Silicon or T2 security chip.
 *
 * If the underlying CryptoTokenKit daemon is unresponsive (a known macOS
 * issue after prolonged uptime), the SDK automatically kills and restarts
 * the daemon, then retries the operation.
 */
// CROSS_IMPL_SYNC: enclave_sign
// Implementations: py:oneid/helper.py go:internal/enclave/sign_darwin.go node:src/helper.ts
export async function sign_challenge_with_enclave(
  nonce_b64: string,
): Promise<Record<string, unknown>> {
  const se_helper_path = find_secure_enclave_helper_binary();
  if (se_helper_path == null) {
    throw new NoHSMError(
      "oneid-se-helper binary not found. "
      + "It should be in ~/.oneid/bin/ alongside oneid-enroll."
    );
  }

  const cmd_args = ["sign", "--tag", ENCLAVE_DEFAULT_KEY_TAG, "--nonce", nonce_b64];

  for (let attempt_number = 0; attempt_number < 2; attempt_number++) {
    try {
      const stdout = child_process.execFileSync(se_helper_path, cmd_args, {
        timeout: SE_HELPER_COMMAND_TIMEOUT_MS,
        encoding: "utf-8",
      });
      const output = JSON.parse(stdout);
      if (output.status !== "ok") {
        throw new HSMAccessError(`oneid-se-helper sign returned error: ${output.error ?? "unknown"}`);
      }
      return output;
    } catch (error: any) {
      if (error instanceof HSMAccessError || error instanceof NoHSMError) { throw error; }
      const timed_out = error?.killed === true || error?.signal === "SIGTERM";
      if (timed_out && attempt_number === 0) {
        if (attempt_macos_cryptotokenkit_daemon_recovery()) { continue; }
      }
      throw new HSMAccessError(`oneid-se-helper sign failed: ${error.message ?? error}`);
    }
  }

  throw new HSMAccessError("oneid-se-helper sign failed after ctkd recovery retry");
}

// ---------------------------------------------------------------------------
// Tier B: Pure-Node PIV signing via the 'smartcard' npm package (optional).
// When 'smartcard' is installed, these functions provide multi-YubiKey
// enumeration, serial-based selection, and direct PIV APDU signing -- all
// without the Go binary.
//
// CROSS_IMPL_SYNC: piv_multi_key
// Implementations: py:oneid/helper.py go:internal/piv/connection.go node:src/helper.ts
// ---------------------------------------------------------------------------

const PIV_AID_FOR_APPLET_SELECT = [0xA0, 0x00, 0x00, 0x03, 0x08];
const YUBIKEY_MANAGEMENT_AID_FOR_SERIAL_AND_FIRMWARE = [
  0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17,
];

/**
 * Result of enumerating a single PIV-capable YubiKey via PC/SC.
 */
export interface EnumeratedYubiKeyInfo {
  reader_name: string;
  serial_number: number | null;
  firmware_version: string | null;
  piv_slot_9a_has_signing_key: boolean;
  pcsc_enumeration_index: number;
}

/**
 * Try to load the optional 'smartcard' npm package.
 * Returns null if not installed.
 */
function _try_load_smartcard_module(): any | null {
  try {
    return require("smartcard");
  } catch {
    return null;
  }
}

/**
 * Parse TLV response from YubiKey management GET DEVICE INFO command.
 * Extracts serial number and firmware version.
 *
 * Tag 0x02 = serial (4 bytes big-endian)
 * Tag 0x05 = firmware version (3 bytes: major.minor.patch)
 */
function _parse_yubikey_management_device_info_tlv_for_serial_and_firmware(
  raw_data: Buffer,
): { serial: number | null; firmware: string | null } {
  let serial: number | null = null;
  let firmware: string | null = null;

  if (raw_data.length < 3) { return { serial, firmware }; }

  // First byte is the total length of TLV data; skip it
  let pos = 1;
  while (pos + 2 <= raw_data.length) {
    const tag = raw_data[pos];
    const len = raw_data[pos + 1];
    pos += 2;
    if (pos + len > raw_data.length) { break; }

    if (tag === 0x02 && len === 4) {
      serial = raw_data.readUInt32BE(pos);
    } else if (tag === 0x05 && len === 3) {
      firmware = `${raw_data[pos]}.${raw_data[pos + 1]}.${raw_data[pos + 2]}`;
    }
    pos += len;
  }

  return { serial, firmware };
}

/**
 * Parse the ASN.1/BER length field at the given offset.
 * Returns [length_value, new_offset].
 */
function _parse_asn1_length(data: Buffer, offset: number): [number, number] {
  if (offset >= data.length) {
    throw new HSMAccessError(`ASN.1 length parse: offset ${offset} beyond data`);
  }
  const first_byte = data[offset];
  if (first_byte < 0x80) {
    return [first_byte, offset + 1];
  }
  const num_length_bytes = first_byte & 0x7F;
  if (num_length_bytes === 0 || offset + 1 + num_length_bytes > data.length) {
    throw new HSMAccessError("ASN.1 length parse: invalid multi-byte length");
  }
  let length_value = 0;
  for (let i = 0; i < num_length_bytes; i++) {
    length_value = (length_value << 8) | data[offset + 1 + i];
  }
  return [length_value, offset + 1 + num_length_bytes];
}

/**
 * Extract the DER signature bytes from a PIV GENERAL AUTHENTICATE response.
 * Response is TLV: tag 0x7C containing tag 0x82 with the signature.
 */
function _extract_signature_from_general_authenticate_response(
  raw_response: Buffer,
): Buffer {
  if (raw_response.length < 4) {
    throw new HSMAccessError(
      `PIV GENERAL AUTHENTICATE response too short: ${raw_response.length} bytes`
    );
  }
  if (raw_response[0] !== 0x7C) {
    throw new HSMAccessError(
      `Unexpected PIV response tag: 0x${raw_response[0].toString(16)} (expected 0x7C)`
    );
  }

  let pos = 1;
  const [, pos_after_outer] = _parse_asn1_length(raw_response, pos);
  pos = pos_after_outer;

  if (pos >= raw_response.length || raw_response[pos] !== 0x82) {
    throw new HSMAccessError(
      `Unexpected inner PIV response tag: 0x${(raw_response[pos] ?? 0).toString(16)} (expected 0x82)`
    );
  }
  pos += 1;
  const [sig_len, pos_after_sig_len] = _parse_asn1_length(raw_response, pos);
  pos = pos_after_sig_len;

  const signature_bytes = raw_response.subarray(pos, pos + sig_len);
  if (signature_bytes.length !== sig_len) {
    throw new HSMAccessError(
      `Truncated PIV signature: expected ${sig_len} bytes, got ${signature_bytes.length}`
    );
  }
  return signature_bytes;
}

/**
 * Check whether the 'smartcard' npm package is available for Tier B operations.
 */
export function is_tier_b_piv_via_smartcard_available(): boolean {
  return _try_load_smartcard_module() !== null;
}

/**
 * Enumerate all connected YubiKeys that have a PIV applet, via PC/SC.
 *
 * Uses the 'smartcard' npm package (optional dependency) to access PC/SC
 * readers directly from Node.js without the Go binary.
 *
 * For each reader that looks like a YubiKey (name contains "yubi" or "ccid"),
 * connects and probes: PIV applet presence, slot 9a key, serial number,
 * firmware version.
 *
 * Requires: npm install smartcard
 */
// CROSS_IMPL_SYNC: piv_multi_key
// Implementations: py:oneid/helper.py go:internal/piv/connection.go node:src/helper.ts
export async function enumerate_all_piv_capable_yubikeys_via_smartcard(): Promise<EnumeratedYubiKeyInfo[]> {
  const smartcard_module = _try_load_smartcard_module();
  if (smartcard_module == null) {
    throw new HSMAccessError(
      "The 'smartcard' npm package is required for Tier B PIV operations. "
      + "Install with: npm install smartcard"
    );
  }

  const { Context, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_PROTOCOL_T1, SCARD_LEAVE_CARD } = smartcard_module;
  const ctx = new Context();
  const detected_yubikeys: EnumeratedYubiKeyInfo[] = [];

  try {
    const all_readers = ctx.listReaders();
    let enumeration_index = 0;

    for (const reader of all_readers) {
      const reader_name_lower = reader.name.toLowerCase();
      if (!reader_name_lower.includes("yubi") && !reader_name_lower.includes("ccid")) {
        continue;
      }
      enumeration_index++;

      const entry: EnumeratedYubiKeyInfo = {
        reader_name: reader.name,
        serial_number: null,
        firmware_version: null,
        piv_slot_9a_has_signing_key: false,
        pcsc_enumeration_index: enumeration_index,
      };

      try {
        const card = await reader.connect(
          SCARD_SHARE_SHARED,
          SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
        );

        try {
          // Step 1: SELECT management applet for serial/firmware (do first
          // because SELECT PIV later will deselect management)
          const select_mgmt_apdu = Buffer.from([
            0x00, 0xA4, 0x04, 0x00,
            YUBIKEY_MANAGEMENT_AID_FOR_SERIAL_AND_FIRMWARE.length,
            ...YUBIKEY_MANAGEMENT_AID_FOR_SERIAL_AND_FIRMWARE,
          ]);
          const mgmt_response = await card.transmit(select_mgmt_apdu);
          const mgmt_sw = mgmt_response.readUInt16BE(mgmt_response.length - 2);

          if (mgmt_sw === 0x9000) {
            const get_info_apdu = Buffer.from([0x00, 0x1D, 0x00, 0x00]);
            const info_response = await card.transmit(get_info_apdu);
            const info_sw = info_response.readUInt16BE(info_response.length - 2);

            if (info_sw === 0x9000 && info_response.length > 2) {
              const info_data = info_response.subarray(0, info_response.length - 2);
              const parsed = _parse_yubikey_management_device_info_tlv_for_serial_and_firmware(info_data);
              entry.serial_number = parsed.serial;
              entry.firmware_version = parsed.firmware;
            }
          }

          // Step 2: SELECT PIV applet
          const select_piv_apdu = Buffer.from([
            0x00, 0xA4, 0x04, 0x00,
            PIV_AID_FOR_APPLET_SELECT.length,
            ...PIV_AID_FOR_APPLET_SELECT,
          ]);
          const piv_response = await card.transmit(select_piv_apdu);
          const piv_sw = piv_response.readUInt16BE(piv_response.length - 2);

          if (piv_sw === 0x9000) {
            // Step 3: Probe slot 9a with GENERAL AUTHENTICATE (same as Python).
            // If the key exists, we get 0x9000 + a signature. If not, 0x6A80.
            const probe_hash = crypto.createHash("sha256").update("phase4-slot-probe").digest();
            const probe_apdu = Buffer.from([
              0x00, 0x87, 0x11, 0x9A, 0x26,
              0x7C, 0x24, 0x82, 0x00, 0x81, 0x20,
              ...probe_hash,
            ]);
            const probe_response = await card.transmit(probe_apdu, { maxRecvLength: 512 });
            const probe_sw = probe_response.readUInt16BE(probe_response.length - 2);
            if (probe_sw === 0x9000) {
              entry.piv_slot_9a_has_signing_key = true;
            }
          }

          card.disconnect(SCARD_LEAVE_CARD);
        } catch {
          try { card.disconnect(SCARD_LEAVE_CARD); } catch { /* ignore */ }
        }
      } catch {
        // Cannot connect to this reader (no card present, locked, etc.)
      }

      detected_yubikeys.push(entry);
    }
  } finally {
    ctx.close();
  }

  return detected_yubikeys;
}

/**
 * Choose which YubiKey reader to use for PIV signing.
 *
 * Priority order (production-ready, matches Python implementation):
 *   1. Explicit serial override -- caller knows which key they want
 *   2. Registered device match -- the serial from credentials/database
 *   3. Most-recently-plugged heuristic -- LAST in PC/SC enumeration
 *      among keys that have a functioning slot 9a key
 *   4. If no key has slot 9a populated, pick the last enumerated anyway
 *   5. Single YubiKey -- no ambiguity, use it
 */
export function select_preferred_piv_yubikey_reader_name(
  available_yubikeys: EnumeratedYubiKeyInfo[],
  preferred_serial_number?: number,
  registered_piv_device_serial_number?: number,
): string | null {
  if (available_yubikeys.length === 0) { return null; }

  if (available_yubikeys.length === 1) {
    return available_yubikeys[0].reader_name;
  }

  // Priority 1: Explicit serial override
  if (preferred_serial_number !== undefined) {
    for (const yk of available_yubikeys) {
      if (yk.serial_number === preferred_serial_number) {
        return yk.reader_name;
      }
    }
    return null;
  }

  // Priority 2: Registered device match
  if (registered_piv_device_serial_number !== undefined) {
    for (const yk of available_yubikeys) {
      if (yk.serial_number === registered_piv_device_serial_number) {
        return yk.reader_name;
      }
    }
  }

  // Priority 3: Last-enumerated key WITH a slot 9a key (most-recently-plugged)
  const yubikeys_with_signing_key = available_yubikeys.filter(
    (yk) => yk.piv_slot_9a_has_signing_key,
  );
  if (yubikeys_with_signing_key.length > 0) {
    return yubikeys_with_signing_key[yubikeys_with_signing_key.length - 1].reader_name;
  }

  // Priority 4: Last-enumerated key (for enrollment or fresh setup)
  return available_yubikeys[available_yubikeys.length - 1].reader_name;
}

/**
 * Sign a nonce using PIV slot 9a on a specific PC/SC reader.
 *
 * Pure Node.js implementation via the 'smartcard' npm package APDUs.
 * Does NOT use the Go binary. This enables signing with a specific
 * YubiKey when multiple are connected (Tier B).
 *
 * The nonce is SHA-256 hashed before sending to the card (matching
 * the Go binary's behavior for ECDSA-SHA256).
 */
export async function sign_nonce_with_specific_piv_reader_via_smartcard(
  nonce_bytes: Buffer,
  reader_name: string,
): Promise<Record<string, unknown>> {
  const smartcard_module = _try_load_smartcard_module();
  if (smartcard_module == null) {
    throw new HSMAccessError(
      "The 'smartcard' npm package is required for Tier B PIV signing. "
      + "Install with: npm install smartcard"
    );
  }

  const { Context, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_PROTOCOL_T1, SCARD_LEAVE_CARD } = smartcard_module;
  const ctx = new Context();

  try {
    const all_readers = ctx.listReaders();
    const target_reader = all_readers.find((r: any) => r.name === reader_name);
    if (target_reader == null) {
      throw new NoHSMError(`PC/SC reader not found: ${reader_name}`);
    }

    const card = await target_reader.connect(
      SCARD_SHARE_SHARED,
      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
    );

    try {
      // SELECT PIV applet
      const select_piv_apdu = Buffer.from([
        0x00, 0xA4, 0x04, 0x00,
        PIV_AID_FOR_APPLET_SELECT.length,
        ...PIV_AID_FOR_APPLET_SELECT,
      ]);
      const piv_response = await card.transmit(select_piv_apdu);
      const piv_sw = piv_response.readUInt16BE(piv_response.length - 2);
      if (piv_sw !== 0x9000) {
        throw new HSMAccessError(
          `PIV applet selection failed: SW=${piv_sw.toString(16).padStart(4, "0")}`
        );
      }

      // Hash the nonce (matching Go binary: ECDSA-SHA256)
      const digest_32_bytes = crypto.createHash("sha256").update(nonce_bytes).digest();

      // GENERAL AUTHENTICATE: P1=0x11 (ECC P-256), P2=0x9A (slot 9a)
      // Data: 7C 24 82 00 81 20 [32 bytes hash]
      const sign_apdu = Buffer.from([
        0x00, 0x87, 0x11, 0x9A, 0x26,
        0x7C, 0x24, 0x82, 0x00, 0x81, 0x20,
        ...digest_32_bytes,
      ]);
      const sign_response = await card.transmit(sign_apdu, { maxRecvLength: 512 });
      const sign_sw = sign_response.readUInt16BE(sign_response.length - 2);

      if (sign_sw === 0x6982) {
        throw new HSMAccessError(
          "PIV slot 9a requires PIN verification (pin-policy is not NEVER). "
          + "This YubiKey may not be configured for agent use."
        );
      }
      if (sign_sw === 0x6A80) {
        throw new HSMAccessError(
          "No key in PIV slot 9a on this YubiKey. "
          + "The key may not be enrolled or may need setup."
        );
      }
      if (sign_sw !== 0x9000) {
        throw new HSMAccessError(
          `PIV signing failed: SW=${sign_sw.toString(16).padStart(4, "0")}`
        );
      }

      // Parse response TLV: 7C [len] 82 [len] [signature bytes]
      const raw_sign_data = sign_response.subarray(0, sign_response.length - 2);
      const signature_der_bytes = _extract_signature_from_general_authenticate_response(raw_sign_data);

      // Get serial number for the response
      let serial_str = "";
      try {
        const select_mgmt = Buffer.from([
          0x00, 0xA4, 0x04, 0x00,
          YUBIKEY_MANAGEMENT_AID_FOR_SERIAL_AND_FIRMWARE.length,
          ...YUBIKEY_MANAGEMENT_AID_FOR_SERIAL_AND_FIRMWARE,
        ]);
        const mgmt_resp = await card.transmit(select_mgmt);
        const mgmt_sw = mgmt_resp.readUInt16BE(mgmt_resp.length - 2);
        if (mgmt_sw === 0x9000) {
          const info_resp = await card.transmit(Buffer.from([0x00, 0x1D, 0x00, 0x00]));
          const info_sw = info_resp.readUInt16BE(info_resp.length - 2);
          if (info_sw === 0x9000 && info_resp.length > 2) {
            const parsed = _parse_yubikey_management_device_info_tlv_for_serial_and_firmware(
              info_resp.subarray(0, info_resp.length - 2),
            );
            if (parsed.serial != null) { serial_str = String(parsed.serial); }
          }
        }
      } catch { /* serial is best-effort */ }

      card.disconnect(SCARD_LEAVE_CARD);
      ctx.close();

      return {
        signature_b64: signature_der_bytes.toString("base64"),
        algorithm: "ECDSA-SHA256",
        serial_number: serial_str,
      };
    } catch (err) {
      try { card.disconnect(SCARD_LEAVE_CARD); } catch { /* ignore */ }
      throw err;
    }
  } catch (err) {
    ctx.close();
    if (err instanceof NoHSMError || err instanceof HSMAccessError) { throw err; }
    throw new HSMAccessError(`Unexpected PIV signing error: ${(err as Error).message ?? err}`);
  }
}
