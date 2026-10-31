import { domainToUnicode } from "node:url";

// URL threat analyzer. Independent of the instruction analyzer and of the PEP: it only DESCRIBES a URL found in untrusted
// content. It never fetches, resolves or visits anything (no DNS, no network) and never authorises anything.
//
// Rule-based and heuristic. No reputation dataset is bundled, so "known malicious" lookups are reported as unavailable and
// a domain with no indicators that is not a known official brand domain is UNKNOWN — never "safe". The registrable-domain
// split is a small built-in approximation, not the Public Suffix List.

export type UrlRisk = "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";

export interface UrlIndicator {
  readonly id:
    | "unparseable"
    | "dangerous-scheme"
    | "non-web-scheme"
    | "userinfo"
    | "unusual-port"
    | "ip-host"
    | "punycode"
    | "mixed-script"
    | "homoglyph-brand"
    | "typosquat-brand"
    | "brand-in-subdomain"
    | "brand-in-hostname"
    | "brand-in-path"
    | "deep-subdomains"
    | "shortener"
    | "encoded-destination"
    | "embedded-redirect"
    | "redirect-target";
  readonly severity: "high" | "medium" | "low";
  readonly reason: string;
}

export interface UrlAssessment {
  /** The URL as found (bounded). */
  readonly url: string;
  readonly scheme: string | null;
  /** Normalised ASCII hostname (lower case, punycode form). */
  readonly hostname: string | null;
  /** Unicode rendering, when the hostname is an internationalised (punycode) name. */
  readonly unicodeHostname: string | null;
  readonly registrableDomain: string | null;
  readonly risk: UrlRisk;
  /** Sum of indicator weights (0–100); null when there is no indicator, so no number is shown without evidence. */
  readonly score: number | null;
  readonly confidence: "high" | "medium" | "low";
  readonly indicators: readonly UrlIndicator[];
  readonly summary: string;
  readonly reputation: "unavailable";
  /** True when the registrable domain is one of the built-in official brand domains. Not a guarantee of safety. */
  readonly knownOfficialDomain: boolean;
}

const MAX_URL_CHARS = 2048;
const WEIGHT = { high: 45, medium: 20, low: 5 } as const;

/** Official domains of commonly impersonated brands (small, fixed list). */
const BRANDS: readonly { name: string; domains: readonly string[] }[] = [
  { name: "paypal", domains: ["paypal.com", "paypal.co.uk", "paypal.de", "paypal.fr", "paypal.com.au", "paypal.ca", "paypal.me"] },
  { name: "google", domains: ["google.com", "gmail.com", "youtube.com", "google.co.uk", "google.co.in", "google.de", "google.fr", "google.co.jp", "google.com.au", "google.ca"] },
  { name: "microsoft", domains: ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"] },
  { name: "apple", domains: ["apple.com", "icloud.com"] },
  { name: "amazon", domains: ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.co.jp", "amazon.com.au", "amazon.ca", "amazonaws.com"] },
  { name: "facebook", domains: ["facebook.com", "fb.com"] },
  { name: "instagram", domains: ["instagram.com"] },
  { name: "netflix", domains: ["netflix.com"] },
  { name: "github", domains: ["github.com"] },
  { name: "linkedin", domains: ["linkedin.com"] },
  { name: "dropbox", domains: ["dropbox.com"] },
  { name: "docusign", domains: ["docusign.com", "docusign.net"] },
  { name: "chase", domains: ["chase.com"] },
  { name: "hdfcbank", domains: ["hdfcbank.com"] },
  { name: "icicibank", domains: ["icicibank.com"] },
  { name: "onlinesbi", domains: ["onlinesbi.sbi", "sbi.co.in"] },
];
const OFFICIAL = new Set(BRANDS.flatMap((b) => b.domains));

const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id"]);
const DANGEROUS_SCHEMES = new Set(["javascript:", "data:", "vbscript:", "file:"]);
const WEB_SCHEMES = new Set(["http:", "https:"]);
/**
 * Shared-hosting suffixes where each customer gets their own subdomain (a tiny subset of the Public Suffix List's private
 * section): "user.github.io" belongs to "user", not to GitHub.
 */
const PRIVATE_SUFFIXES = ["github.io", "blogspot.com", "pages.dev", "netlify.app", "vercel.app", "herokuapp.com", "azurewebsites.net", "web.app", "firebaseapp.com"];
const SECOND_LEVEL = new Set(["co", "com", "org", "net", "gov", "ac", "edu", "gen", "firm", "ind", "nic"]);

/** Visual look-alikes mapped to the Latin letter they imitate (Cyrillic, Greek and digit substitutions). */
const CONFUSABLES: Record<string, string> = {
  а: "a", е: "e", о: "o", р: "p", с: "c", у: "y", х: "x", і: "i", ј: "j", ӏ: "l", ԁ: "d", ѕ: "s", ԛ: "q", ԝ: "w", һ: "h",
  α: "a", ο: "o", ρ: "p", ν: "v", τ: "t", ι: "i", κ: "k", υ: "u", ε: "e",
};
const DIGIT_SUBSTITUTIONS: Record<string, string> = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s" };

const skeleton = (s: string) =>
  [...s.normalize("NFKC").toLowerCase()].map((ch) => CONFUSABLES[ch] ?? DIGIT_SUBSTITUTIONS[ch] ?? ch).join("").replace(/rn/g, "m").replace(/vv/g, "w").replace(/[-_]/g, "");

/** Damerau–Levenshtein (optimal string alignment) distance, bounded inputs. */
function editDistance(a: string, b: string): number {
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i]![j] = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i]![j] = Math.min(d[i]![j]!, d[i - 2]![j - 2]! + 1);
    }
  return d[a.length]![b.length]!;
}

const isIp = (host: string) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.startsWith("[");

export function registrableDomain(host: string): string {
  const priv = PRIVATE_SUFFIXES.find((sfx) => host.endsWith(`.${sfx}`));
  if (priv) return `${host.slice(0, -priv.length - 1).split(".").at(-1)}.${priv}`;
  const labels = host.split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const tld = labels.at(-1)!;
  const sld = labels.at(-2)!;
  const take = tld.length === 2 && SECOND_LEVEL.has(sld) ? 3 : 2;
  return labels.slice(-take).join(".");
}

const officialFor = (domain: string) => OFFICIAL.has(domain) || [...OFFICIAL].some((d) => domain.endsWith(`.${d}`));
/** The label that carries the name (e.g. "paypa1" in paypa1.com, "hdfcbank" in hdfcbank.co.in). */
const nameLabel = (domain: string) => domain.split(".")[0] ?? "";

function brandChecks(host: string, unicodeHost: string, reg: string, path: string, add: (i: UrlIndicator) => void) {
  if (officialFor(reg) || officialFor(host)) return;
  const label = nameLabel(registrableDomain(unicodeHost));
  const labelSkeleton = skeleton(label);
  const plainLabel = label.toLowerCase();
  for (const brand of BRANDS) {
    const b = brand.name;
    if (plainLabel !== b && labelSkeleton === b) {
      const nonAscii = /[^\x00-\x7f]/.test(label);
      add({
        id: nonAscii ? "homoglyph-brand" : "typosquat-brand",
        severity: "high",
        reason: nonAscii
          ? `The domain name uses look-alike characters to imitate "${b}", but it is not ${b}'s official domain.`
          : `The domain name substitutes characters (e.g. digits for letters) to imitate "${b}", but it is not ${b}'s official domain.`,
      });
      return;
    }
    // Look-alikes hidden in one part of a hyphenated name ("amaz0n-support").
    const parts = label.split(/[-_]/).filter((x) => x.length > 0);
    const lookalike = parts.length > 1 ? parts.find((part) => part.toLowerCase() !== b && skeleton(part) === b) : undefined;
    if (lookalike) {
      add({ id: "typosquat-brand", severity: "high", reason: `Part of the domain name imitates "${b}" with substituted characters; it is not ${b}'s official domain.` });
      return;
    }
    // Edit distance only for longer brand names: short ones ("chase") collide with ordinary words ("chaser").
    const dist = b.length >= 6 ? editDistance(labelSkeleton, b) : 99;
    if (plainLabel !== b && dist >= 1 && dist <= (b.length >= 8 ? 2 : 1)) {
      add({ id: "typosquat-brand", severity: "high", reason: `The domain name is one or two characters away from "${b}" (possible typosquatting); it is not ${b}'s official domain.` });
      return;
    }
    if (plainLabel === b) {
      // e.g. paypal.secure-login.test is fine to flag only via subdomain; "paypal.xyz" is the brand on another TLD.
      add({ id: "brand-in-hostname", severity: "medium", reason: `The domain uses the name "${b}" on a domain that is not one of ${b}'s official domains.` });
      return;
    }
    const subLabels = host.slice(0, Math.max(0, host.length - reg.length)).split(/[.-]/).filter(Boolean);
    if (subLabels.some((l) => skeleton(l) === b || (b.length >= 5 && skeleton(l).startsWith(b))) || subLabels.join(".").includes(`${b}.com`)) {
      add({ id: "brand-in-subdomain", severity: "high", reason: `"${b}" appears in the subdomain, but the actual registered domain is ${reg} — a classic misleading hostname boundary.` });
      return;
    }
    if (label.split(/[-_]/).some((part) => part === b)) {
      add({ id: "brand-in-hostname", severity: "medium", reason: `The domain combines the brand name "${b}" with other words; it is not one of ${b}'s official domains.` });
      return;
    }
    if (new RegExp(`\\b${b}(?:\\.com)?\\b`, "i").test(path)) {
      add({ id: "brand-in-path", severity: "medium", reason: `"${b}" appears only in the path; the link actually goes to ${reg}.` });
      return;
    }
  }
}

/** Analyse one URL (or bare host). Pure: no network, no DNS. */
export function analyzeUrl(input: string, depth = 0): UrlAssessment {
  const raw = String(input).trim().slice(0, MAX_URL_CHARS);
  const indicators: UrlIndicator[] = [];
  const add = (i: UrlIndicator) => {
    if (!indicators.some((x) => x.id === i.id)) indicators.push(i);
  };

  const withScheme = /^[a-z][a-z0-9+.-]*:/i.test(raw) ? raw : `http://${raw}`;
  let url: URL | null = null;
  try {
    url = new URL(withScheme);
  } catch {
    url = null;
  }
  if (!url) {
    add({ id: "unparseable", severity: "medium", reason: "The URL could not be parsed, so its real destination cannot be determined." });
    return finish(raw, null, null, null, null, indicators);
  }

  const scheme = url.protocol;
  if (DANGEROUS_SCHEMES.has(scheme)) {
    add({ id: "dangerous-scheme", severity: "high", reason: `The "${scheme}" scheme can run code or read local data instead of opening a web page.` });
    return finish(raw, scheme, null, null, null, indicators);
  }
  if (!WEB_SCHEMES.has(scheme)) add({ id: "non-web-scheme", severity: "medium", reason: `Unusual scheme "${scheme}" for a link in a message.` });

  const host = url.hostname.toLowerCase();
  const unicodeHost = host.includes("xn--") ? domainToUnicode(host) || host : host;
  const reg = isIp(host) ? host : registrableDomain(host);

  if (url.username || url.password)
    add({ id: "userinfo", severity: "high", reason: `Text before "@" in a URL is ignored by browsers; this link really goes to ${host}, not to the name shown before "@".` });
  if (url.port) add({ id: "unusual-port", severity: "medium", reason: `Explicit non-standard port ${url.port}.` });
  if (isIp(host)) add({ id: "ip-host", severity: "medium", reason: "The link points to a raw IP address instead of a domain name." });
  if (/^\d+$|0x/i.test(raw.replace(/^[a-z]+:\/\//i, "").split(/[/:?#]/)[0] ?? ""))
    add({ id: "encoded-destination", severity: "high", reason: "The host is written in a numeric/hex encoded form that hides the real address." });
  if (host.includes("xn--")) {
    add({ id: "punycode", severity: "low", reason: `Internationalised domain name (displayed as "${unicodeHost}").` });
    const scripts = new Set([...unicodeHost].filter((c) => /\p{L}/u.test(c)).map((c) => (/\p{Script=Latin}/u.test(c) ? "Latin" : /\p{Script=Cyrillic}/u.test(c) ? "Cyrillic" : /\p{Script=Greek}/u.test(c) ? "Greek" : "Other")));
    if (scripts.size > 1) add({ id: "mixed-script", severity: "high", reason: "The domain mixes letters from different alphabets, a common way to imitate another domain." });
  }
  if (!isIp(host) && host.split(".").length >= 5) add({ id: "deep-subdomains", severity: "medium", reason: `Unusually many subdomain levels (${host.split(".").length}).` });
  if (SHORTENERS.has(reg) || SHORTENERS.has(host)) add({ id: "shortener", severity: "medium", reason: "URL shortener: the real destination is hidden and was not resolved (AgentShield never visits links)." });

  const decodedPath = safeDecode(url.pathname + url.search + url.hash);
  if (/%[0-9a-f]{2}/i.test(url.pathname + url.search) && (decodedPath.match(/%/g)?.length ?? 0) > 0)
    add({ id: "encoded-destination", severity: "medium", reason: "The URL contains multiple layers of percent-encoding." });
  if (/(?:https?:\/\/|https?%3a)/i.test(url.search + url.hash) || /[?&](?:url|redirect|redirect_uri|next|to|dest|goto)=/i.test(url.search))
  {
    add({ id: "embedded-redirect", severity: "medium", reason: "The URL carries another destination as a parameter (possible open redirect)." });
    // Analyse the embedded destination too (one level, offline), so a redirect through a known site cannot hide it.
    const target = depth === 0 ? [...url.searchParams.values()].find((v) => /^https?:\/\//i.test(v)) : undefined;
    if (target) {
      const inner = analyzeUrl(target, 1);
      if (inner.risk === "HIGH" || inner.risk === "MEDIUM")
        add({
          id: "redirect-target",
          severity: inner.risk === "HIGH" ? "high" : "medium",
          reason: `The embedded destination ${inner.hostname ?? "(unparseable)"} is itself suspicious: ${inner.indicators.map((i) => i.reason).join(" ")}`,
        });
    }
  }

  if (!isIp(host)) brandChecks(host, unicodeHost, reg, decodedPath, add);

  return finish(raw, scheme, host, unicodeHost !== host ? unicodeHost : null, reg, indicators);
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function finish(raw: string, scheme: string | null, host: string | null, unicodeHost: string | null, reg: string | null, indicators: UrlIndicator[]): UrlAssessment {
  const known = reg !== null && host !== null && (officialFor(reg) || officialFor(host));
  const high = indicators.some((i) => i.severity === "high");
  const medium = indicators.some((i) => i.severity === "medium");
  const risk: UrlRisk = high ? "HIGH" : medium ? "MEDIUM" : known ? "LOW" : "UNKNOWN";
  const score = indicators.length ? Math.min(100, indicators.reduce((s, i) => s + WEIGHT[i.severity], 0)) : null;
  const confidence = high ? "high" : medium ? "medium" : known ? "medium" : "low";
  const summary =
    risk === "HIGH"
      ? "Strong indicators of a deceptive or dangerous link."
      : risk === "MEDIUM"
        ? "Suspicious characteristics; the destination should not be trusted without verification."
        : risk === "LOW"
          ? "Matches a known official domain and no impersonation indicators were found. Reputation was not checked; this is not a guarantee of safety."
          : "No indicators found, but the domain is not known and no reputation data is available. Treat as unverified.";
  return Object.freeze({ url: raw.slice(0, 300), scheme, hostname: host, unicodeHostname: unicodeHost, registrableDomain: reg, risk, score, confidence, indicators: Object.freeze(indicators), summary, reputation: "unavailable" as const, knownOfficialDomain: known });
}

/** Find URLs in untrusted text (raw markup included, so href targets are seen). Bounded; never fetches anything. */
export function extractUrls(text: string, max = 20): string[] {
  // Re-fang common defanging ("hxxps://evil[.]test") so obfuscated links are still analysed.
  const src = (typeof text === "string" ? text.slice(0, 100_000) : "").replace(/\bhxxp(s?):/gi, "http$1:").replace(/\[\.\]|\(\.\)|\{\.\}/g, ".");
  const found = new Set<string>();
  const re = /\b(?:https?|ftp|file|javascript|data|vbscript):[^\s"'<>()\]]+|\bwww\.[a-z0-9.-]+\.[a-z]{2,}[^\s"'<>()\]]*/gi;
  for (const m of src.matchAll(re)) {
    found.add(m[0].replace(/[.,;:!?]+$/, ""));
    if (found.size >= max) return [...found];
  }
  // Bare domains ("log in at paypa1.com/verify"): common TLDs only; never the domain of an email address, a file name,
  // or a host already covered by a full URL above.
  const covered = [...found].join(" ").toLowerCase();
  const bare = /(?<![\w@./:-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|in|uk|de|fr|info|biz|xyz|top|app|dev|me|ru|cn|ly)(?![\w@-])(?:\/[^\s"'<>()\]]*)?/gi;
  for (const m of src.matchAll(bare)) {
    const v = m[0].replace(/[.,;:!?]+$/, "");
    if (covered.includes(v.split("/")[0]!.toLowerCase())) continue;
    found.add(v);
    if (found.size >= max) break;
  }
  return [...found];
}
