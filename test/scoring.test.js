import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { analyzeUrl, isIpAddress, MIN_SCORE, MAX_SCORE, SAFE_THRESHOLD } from '../scoring.js';

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

describe('analyzeUrl - individual rules', () => {
  const score = (url) => analyzeUrl(url).score;

  test('clean https domain scores 100', () => {
    assert.equal(score('https://github.com/'), MAX_SCORE);
  });

  test('http instead of https costs 20', () => {
    assert.equal(score('http://example.com/'), 80);
  });

  test('IP address host costs 60 (hex/decimal forms are normalised first)', () => {
    assert.equal(score('https://192.168.1.10/'), 40);
    assert.equal(score('https://0x7f000001/'), 40);
    assert.equal(score('https://[::1]/'), 40);
  });

  test('more than two hyphens costs 20', () => {
    assert.equal(score('https://a-b.com/'), 100);
    assert.equal(score('https://a-b-c-d.com/'), 80);
  });

  test('suspicious keyword in the hostname costs 30, once', () => {
    assert.equal(score('https://secure-login.example.com/'), 70);
    assert.equal(score('https://Login.EXAMPLE.com/'), 70, 'URL parser lower-cases the host');
  });

  test('keywords in the path, query or fragment are ignored', () => {
    assert.equal(score('https://example.com/login?verify=1#account'), 100);
  });

  test('suspicious TLD costs 40', () => {
    assert.equal(score('https://cool.click/'), 60);
    assert.equal(score('https://example.xyz/'), 60);
  });

  test('hostname longer than 40 characters costs 15', () => {
    assert.equal(score(`https://${'a'.repeat(36)}.com/`), 100, '40 chars is fine');
    assert.equal(score(`https://${'a'.repeat(37)}.com/`), 85, '41 chars is not');
  });

  test('a trailing dot on the host is stripped before scoring', () => {
    assert.equal(score('https://example.com./'), 100);
  });
});

describe('analyzeUrl - combination, clamping and status', () => {
  test('penalties add up', () => {
    // 3 hyphens (-20) + keyword (-30) + tld (-40)
    assert.equal(analyzeUrl('https://my-bank-secure-login.xyz/').score, 10);
    // http (-20) + IPv4 (-60)
    assert.equal(analyzeUrl('http://192.168.1.10/login').score, 20);
  });

  test('score never drops below MIN_SCORE', () => {
    // http (-20) + hyphens (-20) + keyword (-30) + tld (-40) = -10
    assert.equal(analyzeUrl('http://verify-account-update-now.tk/').score, MIN_SCORE);
  });

  test('unparseable input is treated as maximally suspicious', () => {
    assert.deepEqual(analyzeUrl('not a url'), { score: MIN_SCORE, status: 'warning' });
    assert.equal(analyzeUrl(undefined).status, 'warning');
  });

  test('status flips from safe to warning below the threshold', () => {
    assert.equal(analyzeUrl('http://example.com/').status, 'safe');            // 80
    assert.equal(analyzeUrl('https://accounts.google.com/').status, 'warning'); // 70
    assert.ok(SAFE_THRESHOLD > 70 && SAFE_THRESHOLD <= 80, 'threshold sits between these fixtures');
  });
});
