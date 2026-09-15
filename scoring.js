/**
 * Phishing Link Detector - heuristic scoring engine.
 *
 * Pure functions only: no chrome.* APIs, no DOM, no network. The background
 * service worker imports analyzeUrl(); the test suite imports everything.
 *
 * Every URL starts at 100 and loses points for each rule that fires. Rules
 * look at the *registrable* domain (the part someone actually paid for), so
 * accounts.google.com is judged as google.com while paypal.com.evil.net is
 * judged as evil.net.
 */
import {
  PUBLIC_SUFFIXES, SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS, TRUSTED_PLATFORMS, URL_SHORTENERS,
} from './lists.js';
import { findBrandAbuse } from './lookalike.js';
import { unwrapRedirects } from './redirects.js';

export const SAFE_THRESHOLD = 75;    // score >= this: "safe"
export const CAUTION_THRESHOLD = 50; // score >= this: "caution", below: "warning"
export const MIN_SCORE = 1;
export const MAX_SCORE = 100;

/* ---------- host parsing ---------- */

export function isIpAddress(hostname) {
  // IPv6 literals keep their brackets in URL.hostname, e.g. "[::1]".
  if (hostname.startsWith('[') && hostname.endsWith(']')) return true;

  // IPv4. The URL parser has already normalised the sneaky octal/hex/decimal
  // forms (http://0x7f000001/ becomes 127.0.0.1), so a strict dotted-quad
  // check is enough here.
  const octets = hostname.split('.');
  return (
    octets.length === 4 &&
    octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)
  );
}

/**
 * Splits a hostname into the parts the rules care about.
 *
 *   describeHost('shop.example.co.uk') -> {
 *     publicSuffix: 'co.uk', registrable: 'example.co.uk', sld: 'example',
 *     subdomain: 'shop', owned: 'shop.example', isIp: false }
 *
 * `owned` is everything the registrant controls (subdomains + SLD).
 */
export function describeHost(hostname) {
  if (isIpAddress(hostname)) {
    return { hostname, isIp: true, publicSuffix: '', registrable: hostname, sld: '', subdomain: '', owned: '' };
  }
  const labels = hostname.split('.');

  // Longest matching public suffix wins; a bare TLD is the fallback.
  let suffixLength = 1;
  for (let i = 0; i < labels.length; i++) {
    if (PUBLIC_SUFFIXES.has(labels.slice(i).join('.'))) {
      suffixLength = labels.length - i;
      break;
    }
  }
  const ownedLabels = labels.slice(0, labels.length - suffixLength);
  return {
    hostname,
    isIp: false,
    publicSuffix: labels.slice(-suffixLength).join('.'),
    registrable: ownedLabels.length ? labels.slice(-(suffixLength + 1)).join('.') : hostname,
    sld: ownedLabels.at(-1) ?? '',
    subdomain: ownedLabels.slice(0, -1).join('.'),
    owned: ownedLabels.join('.'),
  };
}

/* ---------- helpers ---------- */

function countHyphens(hostname) {
  // "xn--" is punycode plumbing, not a choice the registrant made.
  return (hostname.replace(/(^|\.)xn--/g, '$1').match(/-/g) || []).length;
}

function findKeyword(text) {
  return SUSPICIOUS_KEYWORDS.find((word) => text.includes(word));
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

/* ---------- heuristic rules ---------- */

/**
 * Each rule receives { url, host, brand } and returns a human-readable reason
 * when it applies, or a falsy value when it does not. `penalty` is subtracted
 * from the score for every rule that fires.
 */
export const RULES = [
  {
    id: 'lookalike-domain',
    penalty: 60,
    test: ({ brand }) => brand?.kind === 'lookalike' &&
      (brand.idn
        ? `"${brand.token}" spells ${brand.name} with look-alike foreign letters`
        : `"${brand.token}" imitates ${brand.name}`),
  },
  {
    id: 'fake-host-in-userinfo',
    penalty: 60,
    // https://google.com@evil.com/ - the part before @ is a username, not the site.
    test: ({ url }) => url.username.includes('.') && `Pretends to be "${url.username}" but the site is ${url.hostname}`,
  },
  {
    id: 'ip-address-host',
    penalty: 60,
    test: ({ host }) => host.isIp && 'Uses a raw IP address instead of a domain name',
  },
  {
    id: 'brand-impersonation',
    penalty: 50,
    test: ({ brand }) => brand?.kind === 'impersonation' && `Uses the ${brand.name} name but is not a ${brand.name} site`,
  },
  {
    id: 'suspicious-tld',
    penalty: 40,
    test: ({ host }) => {
      const tld = host.hostname.slice(host.hostname.lastIndexOf('.') + 1);
      return SUSPICIOUS_TLDS.has(tld) && `.${tld} domains are frequently used for phishing`;
    },
  },
  {
    id: 'suspicious-keyword',
    penalty: 30,
    test: ({ host }) => {
      const word = findKeyword(host.sld);
      return word && `"${word}" in the domain name`;
    },
  },
  {
    id: 'embedded-credentials',
    penalty: 30,
    test: ({ url }) => url.username !== '' && !url.username.includes('.') && 'Contains a username and password',
  },
  {
    id: 'insecure-protocol',
    penalty: 20,
    test: ({ url }) => url.protocol === 'http:' && 'Not using HTTPS',
  },
  {
    id: 'excessive-hyphens',
    penalty: 20,
    test: ({ host }) => countHyphens(host.hostname) > 2 && 'Unusually many hyphens in the address',
  },
  {
    id: 'long-domain',
    penalty: 15,
    test: ({ host }) => host.hostname.length > 40 && 'Unusually long domain name',
  },
  {
    id: 'idn-characters',
    penalty: 15,
    test: ({ host }) => /(^|\.)xn--/.test(host.hostname) && 'Uses international characters that can imitate familiar letters',
  },
  {
    id: 'subdomain-keyword',
    penalty: 10,
    test: ({ host }) => {
      const word = !findKeyword(host.sld) && findKeyword(host.subdomain);
      return word && `"${word}" in a subdomain`;
    },
  },
];

/* ---------- scoring ---------- */

function statusFor(score) {
  if (score >= SAFE_THRESHOLD) return 'safe';
  if (score >= CAUTION_THRESHOLD) return 'caution';
  return 'warning';
}

/**
 * Scores a URL string.
 *
 * @returns {{
 *   status: 'safe' | 'caution' | 'warning' | 'unknown',
 *   score: number | null,     1..100, or null when the destination cannot be judged
 *   host: string,             registrable domain of the final destination (what to show the user)
 *   url: string,              final destination after unwrapping redirectors
 *   via: string[],            redirector hostnames that were unwrapped, in order
 *   reasons: { id: string, penalty: number, text: string }[]   fired rules, heaviest first
 * }}
 */
export function analyzeUrl(input) {
  let parsed;
  try {
    parsed = new URL(String(input));
  } catch {
    // If it can't even be parsed it can't be vouched for.
    return {
      status: 'warning', score: MIN_SCORE, host: '', url: String(input ?? ''), via: [],
      reasons: [{ id: 'invalid-url', penalty: MAX_SCORE, text: 'Not a valid web address' }],
    };
  }

  const { url, via } = unwrapRedirects(parsed);

  // URL.hostname is already lower-cased and punycoded; only a trailing dot
  // (the fully-qualified "example.com." form) still needs stripping.
  const host = describeHost(url.hostname.replace(/\.$/, ''));

  if (URL_SHORTENERS.has(host.registrable)) {
    return {
      status: 'unknown', score: null, host: host.registrable, url: url.href, via,
      reasons: [{ id: 'url-shortener', penalty: 0, text: 'Shortened link: the real destination is hidden' }],
    };
  }

  const brand = host.isIp || TRUSTED_PLATFORMS.has(host.registrable) ? null : findBrandAbuse(host);
  const subject = { url, host, brand };

  const reasons = [];
  let score = MAX_SCORE;
  for (const rule of RULES) {
    const text = rule.test(subject);
    if (!text) continue;
    reasons.push({ id: rule.id, penalty: rule.penalty, text });
    score -= rule.penalty;
  }
  score = clamp(score, MIN_SCORE, MAX_SCORE);

  return { status: statusFor(score), score, host: host.registrable, url: url.href, via, reasons };
}
