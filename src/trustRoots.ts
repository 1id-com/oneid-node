/**
 * 1id Trust Root Certificate Cache
 *
 * Manages the local cache of 1ID CA root certificates used for offline
 * peer identity verification. The verifier never needs to contact 1ID
 * during verification -- only to refresh the root cache.
 *
 * Cache lifecycle:
 *   1. First call to get_trust_roots() auto-fetches from /api/v1/trust/roots
 *   2. Roots are cached on disk (alongside credentials.json)
 *   3. Subsequent calls use the cache (no network)
 *   4. refresh_trust_roots() explicitly refetches and updates the cache
 *   5. Cache has no expiry -- roots are long-lived (30+ years)
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as https from "node:https";
import * as http from "node:http";
import * as path from "node:path";
import { get_credentials_directory } from "./credentials.js";

const TRUST_ROOTS_CACHE_FILENAME = "trust-roots.pem";
const TRUST_ROOTS_API_PATH = "/api/v1/trust/roots";
const DEFAULT_API_BASE_URL = "https://1id.com";
const FETCH_TIMEOUT_MILLISECONDS = 15_000;

let cached_root_certificates: crypto.X509Certificate[] | null = null;
let cached_root_pem: string | null = null;

function get_trust_roots_cache_path(): string {
  return path.join(get_credentials_directory(), TRUST_ROOTS_CACHE_FILENAME);
}

/**
 * Split a PEM bundle into individual X509Certificate objects.
 */
export function parse_pem_bundle_into_certificates(pem_bundle: string): crypto.X509Certificate[] {
  const certificates: crypto.X509Certificate[] = [];
  const pem_regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let match: RegExpExecArray | null;
  while ((match = pem_regex.exec(pem_bundle)) !== null) {
    try {
      certificates.push(new crypto.X509Certificate(match[0]));
    } catch {
      // skip unparseable blocks
    }
  }
  return certificates;
}

function load_from_cache(): string | null {
  const cache_path = get_trust_roots_cache_path();
  try {
    if (fs.existsSync(cache_path)) {
      const content = fs.readFileSync(cache_path, "utf-8");
      if (content.trim()) { return content; }
    }
  } catch {
    // cache miss
  }
  return null;
}

function save_to_cache(pem_bundle: string): void {
  const cache_path = get_trust_roots_cache_path();
  try {
    fs.mkdirSync(path.dirname(cache_path), { recursive: true });
    fs.writeFileSync(cache_path, pem_bundle, "utf-8");
  } catch {
    // best-effort
  }
}

function fetch_from_server(api_base_url?: string): Promise<string> {
  const base_url = api_base_url ?? DEFAULT_API_BASE_URL;
  const url = new URL(TRUST_ROOTS_API_PATH, base_url);

  return new Promise<string>((resolve, reject) => {
    const transport_module = url.protocol === "https:" ? https : http;
    const request = transport_module.get(url, { timeout: FETCH_TIMEOUT_MILLISECONDS }, (response) => {
      if (response.statusCode !== 200) {
        reject(new Error(`Trust roots fetch failed: HTTP ${response.statusCode}`));
        response.resume();
        return;
      }
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => {
        const pem_bundle = Buffer.concat(chunks).toString("utf-8");
        if (!pem_bundle.includes("-----BEGIN CERTIFICATE-----")) {
          reject(new Error("Server returned invalid trust roots (no PEM certificates found)"));
          return;
        }
        resolve(pem_bundle);
      });
    });
    request.on("error", reject);
    request.on("timeout", () => {
      request.destroy();
      reject(new Error("Trust roots fetch timed out"));
    });
  });
}

/**
 * Fetch current 1ID root certificates from the server and update the local cache.
 *
 * Called automatically on first use of verify_peer_identity(). Can also be
 * called manually to force a refresh.
 */
export async function refresh_trust_roots(api_base_url?: string): Promise<crypto.X509Certificate[]> {
  const pem_bundle = await fetch_from_server(api_base_url);
  const certificates = parse_pem_bundle_into_certificates(pem_bundle);

  if (certificates.length === 0) {
    throw new Error("Trust roots PEM bundle contains no parseable certificates");
  }

  save_to_cache(pem_bundle);
  cached_root_pem = pem_bundle;
  cached_root_certificates = certificates;

  return certificates;
}

/**
 * Get the locally cached 1ID root certificates.
 *
 * If no cache exists, auto-fetches from the server (one-time).
 * Subsequent calls return from the local cache (no network).
 */
export async function get_trust_roots(api_base_url?: string): Promise<crypto.X509Certificate[]> {
  if (cached_root_certificates !== null) {
    return cached_root_certificates;
  }

  const cached_pem = load_from_cache();
  if (cached_pem) {
    const certificates = parse_pem_bundle_into_certificates(cached_pem);
    if (certificates.length > 0) {
      cached_root_pem = cached_pem;
      cached_root_certificates = certificates;
      return certificates;
    }
  }

  return refresh_trust_roots(api_base_url);
}

/**
 * Return the raw PEM bundle of cached trust roots, or null if not loaded.
 */
export function get_trust_roots_pem(): string | null {
  return cached_root_pem;
}
