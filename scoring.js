/**
 * Phishing Link Detector - heuristic scoring engine.
 *
 * Pure functions only: no chrome.* APIs, no DOM, no network. The background
 * service worker imports analyzeUrl() and the test suite imports everything.
 */

export const SAFE_THRESHOLD = 75; // score >= this is "safe", anything lower is "warning"
export const MIN_SCORE = 1;
export const MAX_SCORE = 100;

const SUSPICIOUS_KEYWORDS = ['login', 'secure', 'verify', 'account', 'update'];

// TLDs that are free or nearly free to register and show up disproportionately
// in phishing campaigns. Extend as needed.
const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'tk', 'click',
  'ml', 'ga', 'cf', 'gq',
  'buzz', 'icu', 'work', 'cam', 'rest', 'monster', 'zip', 'mov',
]);

/* ---------- helpers ---------- */

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

function countChar(str, char) {
  let count = 0;
  for (const c of str) if (c === char) count += 1;
  return count;
}

function getTld(hostname) {
  const lastDot = hostname.lastIndexOf('.');
  return lastDot === -1 ? '' : hostname.slice(lastDot + 1);
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

/* ---------- heuristic rules ---------- */

/**
 * Each rule inspects { protocol, hostname } and returns true when it applies.
 * `penalty` is subtracted from the score for every rule that fires.
 */
export const RULES = [
  {
    id: 'insecure-protocol',
    penalty: 20,
    test: ({ protocol }) => protocol === 'http:',
  },
  {
    id: 'ip-address-host',
    penalty: 60,
    test: ({ hostname }) => isIpAddress(hostname),
  },
  {
    id: 'excessive-hyphens',
    penalty: 20,
    test: ({ hostname }) => countChar(hostname, '-') > 2,
  },
  {
    id: 'suspicious-keyword',
    penalty: 30,
    test: ({ hostname }) => SUSPICIOUS_KEYWORDS.some((word) => hostname.includes(word)),
  },
  {
    id: 'suspicious-tld',
    penalty: 40,
    test: ({ hostname }) => SUSPICIOUS_TLDS.has(getTld(hostname)),
  },
  {
    id: 'long-domain',
    penalty: 15,
    test: ({ hostname }) => hostname.length > 40,
  },
];

/* ---------- scoring engine ---------- */

/**
 * Scores a URL string. Returns { score, status } where score is 1..100 and
 * status is "safe" (score >= SAFE_THRESHOLD) or "warning".
 */
export function analyzeUrl(input) {
  let url;
  try {
    url = new URL(String(input));
  } catch {
    // If it can't even be parsed it can't be vouched for.
    return { score: MIN_SCORE, status: 'warning' };
  }

  // URL.hostname is already lower-cased and punycoded; only a trailing dot
  // (the fully-qualified "example.com." form) still needs stripping.
  const subject = {
    protocol: url.protocol,
    hostname: url.hostname.replace(/\.$/, ''),
  };

  let score = MAX_SCORE;
  for (const rule of RULES) {
    if (rule.test(subject)) score -= rule.penalty;
  }
  score = clamp(score, MIN_SCORE, MAX_SCORE);

  return {
    score,
    status: score >= SAFE_THRESHOLD ? 'safe' : 'warning',
  };
}
