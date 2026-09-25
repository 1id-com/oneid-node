/**
 * The ONE version identity of the 1id Node SDK (AUD-F53: index.ts, cli.ts and
 * three User-Agent strings used to report five different versions). Keep equal
 * to package.json "version" (a unit test enforces it).
 */
export const SDK_VERSION = "3.1.1";

/** User-Agent sent on every SDK HTTP request. */
export const SDK_USER_AGENT = `oneid-sdk-node/${SDK_VERSION}`;
