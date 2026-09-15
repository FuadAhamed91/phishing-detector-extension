/**
 * Phishing Link Detector - brand look-alike detection.
 *
 * Finds hostnames that borrow or imitate a well-known brand name:
 *   - the brand name itself on a domain the brand does not own
 *     (paypal.com.evil.net, secure-paypal.com, paypal-verify.blogspot.com)
 *   - digits or letter pairs standing in for letters (amaz0n, rnicrosoft)
 *   - internationalised labels whose letters merely look Latin
 *     (xn--80ak6aa92e is Cyrillic "аррӏе", indistinguishable from apple)
 *   - one-typo variants of longer brand names (googel, linkedln, facebok)
 */
import { BRANDS, LOOKALIKE_STOPWORDS } from './lists.js';

/* ---------- punycode decoding (RFC 3492) ---------- */

const BASE = 36;
const T_MIN = 1;
const T_MAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;

function basicToDigit(codePoint) {
  if (codePoint >= 0x30 && codePoint < 0x3a) return 26 + (codePoint - 0x30); // 0-9
  if (codePoint >= 0x41 && codePoint < 0x5b) return codePoint - 0x41;        // A-Z
  if (codePoint >= 0x61 && codePoint < 0x7b) return codePoint - 0x61;        // a-z
  return BASE;
}

function adapt(delta, numPoints, firstTime) {
  let k = 0;
  delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  for (; delta > ((BASE - T_MIN) * T_MAX) >> 1; k += BASE) {
    delta = Math.floor(delta / (BASE - T_MIN));
  }
  return Math.floor(k + ((BASE - T_MIN + 1) * delta) / (delta + SKEW));
}

/** Decodes the part of an IDNA label after "xn--". Throws on malformed input. */
export function punycodeDecode(input) {
  const output = [];
  let i = 0;
  let n = INITIAL_N;
  let bias = INITIAL_BIAS;

  // Everything before the last '-' is copied through as plain ASCII.
  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) {
    const code = input.charCodeAt(j);
    if (code >= 0x80) throw new RangeError('Illegal non-ASCII input');
    output.push(code);
  }

  for (let index = basic > 0 ? basic + 1 : 0; index < input.length; ) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) throw new RangeError('Invalid punycode');
      const digit = basicToDigit(input.charCodeAt(index++));
      if (digit >= BASE) throw new RangeError('Invalid punycode');
      if (digit > Math.floor((0x7fffffff - i) / w)) throw new RangeError('Overflow');
      i += digit * w;
      const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
      if (digit < t) break;
      if (w > Math.floor(0x7fffffff / (BASE - t))) throw new RangeError('Overflow');
      w *= BASE - t;
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    if (Math.floor(i / out) > 0x7fffffff - n) throw new RangeError('Overflow');
    n += Math.floor(i / out);
    i %= out;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

/** "xn--mnchen-3ya" -> "münchen"; plain or malformed labels come back unchanged. */
export function decodeLabel(label) {
  if (!label.startsWith('xn--')) return label;
  try {
    return punycodeDecode(label.slice(4));
  } catch {
    return label;
  }
}

/* ---------- folding non-Latin look-alikes to ASCII ---------- */

/** Letters from other scripts that are visually identical to a Latin letter. */
const CONFUSABLES = new Map(Object.entries({
  // Cyrillic
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j',
  'ѕ': 's', 'һ': 'h', 'ԁ': 'd', 'ɡ': 'g', 'ԛ': 'q', 'ԝ': 'w', 'ӏ': 'l', 'к': 'k', 'м': 'm',
  'т': 't', 'в': 'b', 'н': 'h', 'ь': 'b', 'г': 'r', 'ԍ': 'g',
  // Greek
  'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'ι': 'i', 'κ': 'k', 'τ': 't', 'υ': 'u', 'χ': 'x',
  'β': 'b', 'η': 'n', 'γ': 'y', 'ω': 'w', 'ς': 's', 'ϲ': 'c', 'ϳ': 'j',
  // Armenian
  'ո': 'n', 'օ': 'o', 'ս': 'u', 'ց': 'g', 'հ': 'h', 'յ': 'j',
  // Latin letters without a plain-letter decomposition
  'ı': 'i', 'ł': 'l', 'ø': 'o', 'đ': 'd', 'ħ': 'h', 'ŧ': 't', 'ɑ': 'a', 'ɩ': 'i', 'ǀ': 'l',
}));

/**
 * Lower-cases, strips accents (é -> e, ü -> u) and swaps confusable letters for
 * the Latin letter they resemble, so "pаypаl" (Cyrillic а) becomes "paypal".
 */
export function foldToAscii(str) {
  const stripped = str.toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '');
  let out = '';
  for (const ch of stripped) out += CONFUSABLES.get(ch) ?? ch;
  return out;
}

/** "paypal.com-secure" -> ["paypal", "com", "secure"]; drops non-alphanumerics. */
export function tokenize(str) {
  return str.split(/[^a-z0-9]+/).filter(Boolean);
}

/* ---------- ASCII imitation: digits, letter pairs, single typos ---------- */

const DIGIT_LOOKALIKES = { 0: 'o', 1: 'il', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b', 9: 'g' };
const PAIR_LOOKALIKES = [['rn', 'm'], ['vv', 'w']];

/** True when `token` reads as `brand` once digits / letter pairs are taken as the letters they resemble. */
function matchesWithHomoglyphs(token, brand) {
  if (token === brand) return false;
  const variants = new Set([token]);
  for (const [pair, letter] of PAIR_LOOKALIKES) {
    for (const v of [...variants]) if (v.includes(pair)) variants.add(v.replaceAll(pair, letter));
  }
  for (const v of variants) {
    if (v.length !== brand.length) continue;
    let same = true;
    for (let i = 0; i < v.length && same; i++) {
      same = v[i] === brand[i] || (DIGIT_LOOKALIKES[v[i]] || '').includes(brand[i]);
    }
    if (same) return true;
  }
  return false;
}

/** Optimal-string-alignment distance == 1: one insertion, deletion, substitution or adjacent swap. */
function isOneEditAway(a, b) {
  if (a === b || Math.abs(a.length - b.length) > 1) return false;
  const d = [];
  for (let i = 0; i <= a.length; i++) {
    d[i] = new Array(b.length + 1).fill(0);
    d[i][0] = i;
  }
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[a.length][b.length] === 1;
}

/* ---------- putting it together ---------- */

// Brands shorter than this are too easy to hit by accident with a one-letter
// typo ("chase" vs "chose"), so they only match exactly or via homoglyphs.
const MIN_TYPO_BRAND_LENGTH = 6;

/**
 * Inspects the part of a hostname its registrant controls (subdomains + SLD,
 * public suffix removed) for brand names it has no right to.
 *
 * @param {{ owned: string, sld: string }} host  e.g. { owned: 'paypal.com.evil', sld: 'evil' }
 * @returns {null | { kind: 'impersonation' | 'lookalike', brand: string, name: string, token: string, idn: boolean }}
 */
export function findBrandAbuse({ owned, sld }) {
  if (!owned) return null;

  // Each token remembers the label it came from, so an IDN hit can be reported
  // by its punycode form (showing the decoded letters would look exactly like
  // the brand to the user, which is the whole problem).
  const tokens = owned.split('.').flatMap((raw) => {
    const idn = raw.startsWith('xn--');
    return tokenize(idn ? foldToAscii(decodeLabel(raw)) : raw)
      .filter((text) => !LOOKALIKE_STOPWORDS.has(text))
      .map((text) => ({ text, idn, shown: idn ? raw : text }));
  });
  const plainJoined = tokens.filter((t) => !t.idn).map((t) => t.text).join(''); // "wells-fargo" -> "wellsfargo"

  for (const brand of BRANDS) {
    if (sld === brand.token || brand.owned.includes(sld)) continue; // the brand's own site
    const { token } = brand;
    const long = token.length >= MIN_TYPO_BRAND_LENGTH;
    const hit = (kind, found) => ({ kind, brand: token, name: brand.name, token: found.shown, idn: found.idn });

    // 1. The brand name itself on someone else's domain. Written plainly it is
    //    impersonation; written in look-alike letters it is a look-alike.
    const exact = tokens.find((t) => t.text === token || (long && t.text.includes(token)));
    if (exact) return hit(exact.idn ? 'lookalike' : 'impersonation', exact);
    if (long && plainJoined.includes(token)) return hit('impersonation', { shown: owned, idn: false });

    // 2. Digits, letter pairs or a single typo standing in for the real spelling.
    for (const t of tokens) {
      if (matchesWithHomoglyphs(t.text, token)) return hit('lookalike', t);
      if (long && isOneEditAway(t.text, token)) return hit('lookalike', t);
    }
  }
  return null;
}
