/**
 * Phishing Link Detector - redirector unwrapping.
 *
 * Mail clients and big platforms wrap outbound links in their own redirect
 * (google.com/url?q=..., safelinks.protection.outlook.com/?url=...). Scoring
 * the wrapper would rate every link in Gmail as "google.com: 100% safe", so
 * the real destination is dug out first.
 */

/** How many nested wrappers to peel (Safe Links around a Google redirect around ...). */
export const MAX_REDIRECT_HOPS = 3;

/**
 * Each entry matches a wrapper by hostname (and optionally path) and says
 * where the destination lives: in one of `params`, or computed by `resolve`.
 */
const REDIRECTORS = [
  // Google search results, Docs, Calendar, Gmail (any Google ccTLD): /url?q= or /url?url=
  { host: /(^|\.)google(\.[a-z]{2,3}){1,2}$/, path: /^\/url\/?$/, params: ['q', 'url'] },
  // Google AMP cache: /amp/s/example.com/page -> https://example.com/page
  { host: /(^|\.)google\.com$/, path: /^\/amp\/s\/.+/, resolve: (url) => `https://${url.pathname.slice('/amp/s/'.length)}${url.search}` },
  // YouTube's "leaving YouTube" interstitial
  { host: /(^|\.)youtube\.com$/, path: /^\/redirect$/, params: ['q'] },
  // Microsoft Defender Safe Links (Outlook, Microsoft 365)
  { host: /(^|\.)safelinks\.protection\.outlook\.com$/, params: ['url'] },
  // Facebook / Instagram link shim
  { host: /^(l|lm|m)\.(facebook|instagram)\.com$/, path: /^\/l\.php$/, params: ['u'] },
  // Slack, Reddit, Tumblr
  { host: /^slack-redir\.net$/, params: ['url'] },
  { host: /^out\.reddit\.com$/, params: ['url'] },
  { host: /^t\.umblr\.com$/, params: ['z'] },
  // Barracuda Link Protect
  { host: /^linkprotect\.cudasvc\.com$/, params: ['a'] },
  // Proofpoint URL Defense v2 (?u=https-3A__...) and v3 (/v3/__https://...__;...)
  { host: /(^|\.)urldefense\.(com|proofpoint\.com)$/, resolve: decodeProofpoint },
];

function decodeProofpoint(url) {
  const v3 = url.pathname.match(/^\/v3\/__(.+?)__;/);
  if (v3) {
    // v3 replaces some characters with '*' and stores them in a trailing
    // base64 blob; without that decoding the URL would be wrong, so bail.
    return v3[1].includes('*') ? null : v3[1];
  }
  const u = url.searchParams.get('u');
  if (url.pathname.startsWith('/v2/') && u) {
    // v2 encodes '/' as '_' and any other special character as -XX (hex).
    return u.replace(/_|-([0-9A-Fa-f]{2})/g, (match, hex) =>
      hex ? String.fromCharCode(parseInt(hex, 16)) : '/');
  }
  return null;
}

function unwrapOnce(url) {
  for (const redirector of REDIRECTORS) {
    if (!redirector.host.test(url.hostname)) continue;
    if (redirector.path && !redirector.path.test(url.pathname)) continue;

    const candidates = redirector.resolve
      ? [redirector.resolve(url)]
      : redirector.params.map((name) => url.searchParams.get(name));

    for (const candidate of candidates) {
      if (!candidate) continue;
      let target;
      try {
        target = new URL(candidate);
      } catch {
        continue;
      }
      if (target.protocol === 'http:' || target.protocol === 'https:') return target;
    }
  }
  return null;
}

/**
 * Follows known wrappers to the real destination.
 *
 * @param {URL} url
 * @returns {{ url: URL, via: string[] }} the final URL and the wrapper hostnames peeled, in order
 */
export function unwrapRedirects(url) {
  const via = [];
  let current = url;
  for (let hop = 0; hop < MAX_REDIRECT_HOPS; hop++) {
    const next = unwrapOnce(current);
    if (!next) break;
    via.push(current.hostname);
    current = next;
  }
  return { url: current, via };
}
