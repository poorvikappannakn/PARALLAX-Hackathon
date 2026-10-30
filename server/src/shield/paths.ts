// Logical sandbox paths, as seen by policy. Tools additionally resolve + realpath against the
// per-run sandbox root (M2); this layer rejects anything that is not a plain relative path.

const WINDOWS_DEVICE = /^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$/i;

/** Returns a lower-cased, forward-slash relative path, or null if the input could escape or alias. */
export function normalizeSandboxPath(input: unknown): string | null {
  if (typeof input !== "string" || input.length === 0 || input.length > 256) return null;
  if (/[\u0000-\u001f]/.test(input)) return null; // NUL and control characters
  const p = input.replace(/\\/g, "/");
  if (p.startsWith("/")) return null; // absolute or UNC (//host/share)
  if (p.includes(":")) return null; // drive letters (C:) and NTFS alternate data streams
  if (p.includes("~")) return null; // 8.3 short names / home expansion
  const segments = p.split("/").filter((s) => s !== "" && s !== ".");
  if (segments.length === 0) return null;
  for (const s of segments) {
    if (s === "..") return null;
    if (/[. ]$/.test(s)) return null; // Windows strips trailing dots/spaces -> aliasing
    if (WINDOWS_DEVICE.test(s)) return null;
  }
  return segments.join("/").toLowerCase();
}

/** Scopes are lower-case directory prefixes ending in "/". */
export function isWithinScopes(normalizedPath: string, scopes: readonly string[]): boolean {
  return scopes.some((scope) => normalizedPath.startsWith(scope.toLowerCase()));
}
