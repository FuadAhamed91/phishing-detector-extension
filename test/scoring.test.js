import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  analyzeUrl, describeHost, isIpAddress, RULES,
  MIN_SCORE, MAX_SCORE, SAFE_THRESHOLD, CAUTION_THRESHOLD,
} from '../scoring.js';

const ids = (url) => analyzeUrl(url).reasons.map((r) => r.id);
const score = (url) => analyzeUrl(url).score;

describe('isIpAddress', () => {
  test('recognises dotted-quad IPv4 and bracketed IPv6', () => {
    assert.equal(isIpAddress('192.168.1.10'), true);
    assert.equal(isIpAddress('[::1]'), true);
    assert.equal(isIpAddress('[2001:db8::1]'), true);
  });

  test('rejects domain names and malformed quads', () => {
    assert.equal(isIpAddress('example.com'), false);
    assert.equal(isIpAddress('1.2.3'), false);
    assert.equal(isIpAddress('256.1.1.1'), false);
    assert.equal(isIpAddress('1.2.3.4.5'), false);
  });
});

describe('describeHost', () => {
  test('plain TLD: the last two labels are the registrable domain', () => {
    assert.deepEqual(describeHost('accounts.google.com'), {
      hostname: 'accounts.google.com', isIp: false, publicSuffix: 'com',
      registrable: 'google.com', sld: 'google', subdomain: 'accounts', owned: 'accounts.google',
    });
  });

  test('multi-label public suffixes are respected', () => {
    assert.equal(describeHost('shop.example.co.uk').registrable, 'example.co.uk');
    assert.equal(describeHost('shop.example.co.uk').sld, 'example');
    assert.equal(describeHost('shop.example.co.uk').publicSuffix, 'co.uk');
  });

  test('hosting providers: the customer label is the registrable part', () => {
    assert.equal(describeHost('evil.github.io').registrable, 'evil.github.io');
    assert.equal(describeHost('evil.github.io').sld, 'evil');
    assert.equal(describeHost('bucket.s3.amazonaws.com').owned, 'bucket');
    assert.equal(describeHost('paypal-verify.blogspot.com').sld, 'paypal-verify');
  });

  test('edge cases: bare suffix, single label, IP address', () => {
    assert.equal(describeHost('github.io').registrable, 'github.io');
    assert.equal(describeHost('github.io').owned, '');
    assert.equal(describeHost('localhost').registrable, 'localhost');
    assert.deepEqual(describeHost('10.0.0.1'), {
      hostname: '10.0.0.1', isIp: true, publicSuffix: '', registrable: '10.0.0.1', sld: '', subdomain: '', owned: '',
    });
  });
});

describe('rules', () => {
  test('are ordered heaviest first so reasons come out sorted', () => {
    const penalties = RULES.map((r) => r.penalty);
    assert.deepEqual(penalties, [...penalties].sort((a, b) => b - a));
  });

  test('clean https domain: nothing fires', () => {
    assert.deepEqual(ids('https://github.com/'), []);
    assert.equal(score('https://github.com/'), MAX_SCORE);
  });

  test('insecure-protocol (-20)', () => {
    assert.deepEqual(ids('http://example.com/'), ['insecure-protocol']);
    assert.equal(score('http://example.com/'), 80);
  });

  test('ip-address-host (-60), including hex/decimal forms the parser normalises', () => {
    assert.deepEqual(ids('https://192.168.1.10/'), ['ip-address-host']);
    assert.deepEqual(ids('https://0x7f000001/'), ['ip-address-host']);
    assert.deepEqual(ids('https://[::1]/'), ['ip-address-host']);
    assert.equal(score('https://192.168.1.10/'), 40);
  });

  test('excessive-hyphens (-20) counts hyphens the registrant chose, not xn-- plumbing', () => {
    assert.deepEqual(ids('https://a-b.com/'), []);
    assert.deepEqual(ids('https://a-b-c-d.com/'), ['excessive-hyphens']);
    assert.ok(!ids('https://xn--mller-kva.de/').includes('excessive-hyphens'));
  });

  test('suspicious-keyword (-30) looks at the registrable label only', () => {
    assert.deepEqual(ids('https://secure-login.com/'), ['suspicious-keyword']);
    assert.deepEqual(ids('https://Login.EXAMPLE.com/'), ['subdomain-keyword'], 'parser lower-cases; keyword is in a subdomain');
    assert.deepEqual(ids('https://example.com/login?verify=1#account'), [], 'path, query and fragment are ignored');
  });

  test('subdomain-keyword (-10) is mild and never doubles up with the domain rule', () => {
    assert.deepEqual(ids('https://accounts.google.com/'), ['subdomain-keyword']);
    assert.equal(score('https://accounts.google.com/'), 90);
    assert.deepEqual(ids('https://login.secure-pay.com/'), ['suspicious-keyword']);
  });

  test('suspicious-tld (-40)', () => {
    assert.deepEqual(ids('https://cool.click/'), ['suspicious-tld']);
    assert.deepEqual(ids('https://example.xyz/'), ['suspicious-tld']);
    assert.equal(score('https://example.xyz/'), 60);
  });

  test('long-domain (-15): more than 40 characters', () => {
    assert.deepEqual(ids(`https://${'a'.repeat(36)}.com/`), []);
    assert.deepEqual(ids(`https://${'a'.repeat(37)}.com/`), ['long-domain']);
  });

  test('idn-characters (-15) alone leaves a legitimate umlaut domain green', () => {
    const verdict = analyzeUrl('https://xn--mller-kva.de/');
    assert.deepEqual(verdict.reasons.map((r) => r.id), ['idn-characters']);
    assert.equal(verdict.status, 'safe');
  });

  test('fake-host-in-userinfo (-60): a domain before @ is a username, not the site', () => {
    const verdict = analyzeUrl('https://google.com@evil.com/');
    assert.deepEqual(verdict.reasons.map((r) => r.id), ['fake-host-in-userinfo']);
    assert.equal(verdict.host, 'evil.com');
    assert.match(verdict.reasons[0].text, /google\.com/);
  });

  test('embedded-credentials (-30) for plain basic-auth style userinfo', () => {
    assert.deepEqual(ids('https://admin:hunter2@example.com/'), ['embedded-credentials']);
  });

  test('brand-impersonation (-50) fires for a brand on a domain it does not own', () => {
    assert.deepEqual(ids('https://paypal.com.evil.net/'), ['brand-impersonation']);
    assert.deepEqual(ids('https://paypal-verify.blogspot.com/'), ['brand-impersonation', 'suspicious-keyword']);
    assert.match(analyzeUrl('https://paypal.com.evil.net/').reasons[0].text, /PayPal/);
  });

  test('brand-impersonation stays quiet on the brand\'s own domains and company family', () => {
    for (const url of [
      'https://www.paypalobjects.com/', 'https://itunes.apple.com/', 'https://outlook.office.com/',
      'https://login.microsoftonline.com/', 'https://bucket.s3.amazonaws.com/', 'https://finance.yahoo.com/',
    ]) {
      assert.ok(!ids(url).includes('brand-impersonation'), url);
    }
  });

  test('brand names in subdomains of trusted platforms are communities, not fakes', () => {
    assert.deepEqual(ids('https://apple.stackexchange.com/'), []);
  });

  test('lookalike-domain (-60) for typos, digits, letter pairs and foreign letters', () => {
    assert.deepEqual(ids('https://amaz0n.com/'), ['lookalike-domain']);
    assert.deepEqual(ids('https://rnicrosoft.com/'), ['lookalike-domain']);
    assert.deepEqual(ids('https://googel.com/'), ['lookalike-domain']);
    // Cyrillic "аррӏе"
    assert.deepEqual(ids('https://xn--80ak6aa92e.com/'), ['lookalike-domain', 'idn-characters']);
    assert.match(analyzeUrl('https://xn--80ak6aa92e.com/').reasons[0].text, /xn--80ak6aa92e.*Apple/);
  });
});

describe('analyzeUrl - verdicts', () => {
  test('tiers: safe >= 75, caution >= 50, warning below', () => {
    assert.equal(SAFE_THRESHOLD, 75);
    assert.equal(CAUTION_THRESHOLD, 50);
    assert.equal(analyzeUrl('http://example.com/').status, 'safe');       // 80
    assert.equal(analyzeUrl('https://example.xyz/').status, 'caution');   // 60
    assert.equal(analyzeUrl('https://amaz0n.com/').status, 'warning');    // 40
  });

  test('penalties add up and reasons come back heaviest first', () => {
    const verdict = analyzeUrl('https://my-bank-secure-login.xyz/');
    assert.equal(verdict.score, 10); // tld 40 + keyword 30 + hyphens 20
    assert.deepEqual(verdict.reasons.map((r) => r.penalty), [40, 30, 20]);
    assert.equal(analyzeUrl('http://192.168.1.10/login').score, 20);
  });

  test('score never drops below MIN_SCORE', () => {
    assert.equal(analyzeUrl('http://verify-account-update-now.tk/').score, MIN_SCORE);
  });

  test('host is the registrable domain of the destination, url is the final URL', () => {
    const verdict = analyzeUrl('https://paypal.com.account-services.net/login');
    assert.equal(verdict.host, 'account-services.net');
    assert.equal(verdict.url, 'https://paypal.com.account-services.net/login');
    assert.equal(verdict.status, 'warning');
    assert.equal(verdict.score, 20);
  });

  test('redirectors are unwrapped and reported in via', () => {
    const verdict = analyzeUrl('https://www.google.com/url?q=https://evil.xyz&source=gmail');
    assert.equal(verdict.host, 'evil.xyz');
    assert.equal(verdict.url, 'https://evil.xyz/');
    assert.deepEqual(verdict.via, ['www.google.com']);
    assert.equal(verdict.status, 'caution');
  });

  test('URL shorteners get an "unknown" verdict with no score', () => {
    const verdict = analyzeUrl('https://bit.ly/3xyz');
    assert.equal(verdict.status, 'unknown');
    assert.equal(verdict.score, null);
    assert.equal(verdict.host, 'bit.ly');
    assert.deepEqual(verdict.reasons.map((r) => r.id), ['url-shortener']);
  });

  test('unparseable input is treated as maximally suspicious', () => {
    const verdict = analyzeUrl('not a url');
    assert.equal(verdict.status, 'warning');
    assert.equal(verdict.score, MIN_SCORE);
    assert.deepEqual(verdict.reasons.map((r) => r.id), ['invalid-url']);
    assert.equal(analyzeUrl(undefined).status, 'warning');
  });

  test('a trailing dot on the host is stripped before scoring', () => {
    assert.equal(analyzeUrl('https://example.com./').host, 'example.com');
    assert.equal(score('https://example.com./'), MAX_SCORE);
  });
});

describe('analyzeUrl - realistic fixtures', () => {
  const fixtures = [
    ['https://github.com/', 'safe'],
    ['https://accounts.google.com/', 'safe'],
    ['https://login.microsoftonline.com/', 'safe'],
    ['https://xn--mller-kva.de/', 'safe'],
    ['https://apple.stackexchange.com/', 'safe'],
    ['https://www.google.com/url?q=https://evil.xyz', 'caution'],
    ['https://paypal.com.account-services.net/', 'warning'],
    ['https://paypal.com-secure.net/', 'warning'],
    ['https://google.com@evil.com/', 'warning'],
    ['https://amaz0n.com/', 'warning'],
    ['https://xn--80ak6aa92e.com/', 'warning'],
    ['https://wells-fargo-login.com/', 'warning'],
    ['http://192.168.1.10/login', 'warning'],
    ['https://bit.ly/3xyz', 'unknown'],
  ];

  for (const [url, expected] of fixtures) {
    test(`${url} -> ${expected}`, () => {
      assert.equal(analyzeUrl(url).status, expected);
    });
  }
});
