import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { unwrapRedirects, MAX_REDIRECT_HOPS } from '../redirects.js';

const unwrap = (url) => {
  const { url: final, via } = unwrapRedirects(new URL(url));
  return { url: final.href, via };
};

describe('unwrapRedirects', () => {
  test('leaves ordinary links alone', () => {
    assert.deepEqual(unwrap('https://example.com/path?q=https://other.com'), {
      url: 'https://example.com/path?q=https://other.com', via: [],
    });
  });

  test('Google /url on any ccTLD, with q= or url=', () => {
    assert.deepEqual(unwrap('https://www.google.com/url?q=https://evil.xyz/a&source=gmail&ust=1'), {
      url: 'https://evil.xyz/a', via: ['www.google.com'],
    });
    assert.equal(unwrap('https://www.google.co.uk/url?sa=t&url=https%3A%2F%2Fexample.org%2F').url, 'https://example.org/');
    assert.equal(unwrap('https://google.com/url').via.length, 0, 'no destination parameter, nothing to unwrap');
  });

  test('Google AMP cache', () => {
    assert.deepEqual(unwrap('https://www.google.com/amp/s/www.example.com/news/story?x=1'), {
      url: 'https://www.example.com/news/story?x=1', via: ['www.google.com'],
    });
  });

  test('YouTube, Facebook, Slack, Reddit, Tumblr, Barracuda', () => {
    assert.equal(unwrap('https://www.youtube.com/redirect?q=https%3A%2F%2Fexample.com&v=abc').url, 'https://example.com/');
    assert.equal(unwrap('https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.com%2Fx&h=AT0').url, 'https://example.com/x');
    assert.equal(unwrap('https://slack-redir.net/link?url=https%3A%2F%2Fexample.com').url, 'https://example.com/');
    assert.equal(unwrap('https://out.reddit.com/t3_x?url=https%3A%2F%2Fexample.com').url, 'https://example.com/');
    assert.equal(unwrap('https://t.umblr.com/redirect?z=https%3A%2F%2Fexample.com&t=abc').url, 'https://example.com/');
    assert.equal(unwrap('https://linkprotect.cudasvc.com/url?a=https%3A%2F%2Fexample.com&c=E').url, 'https://example.com/');
  });

  test('Microsoft Safe Links', () => {
    const wrapped = 'https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.com%2Fdoc&data=05%7C01';
    assert.deepEqual(unwrap(wrapped), { url: 'https://example.com/doc', via: ['nam12.safelinks.protection.outlook.com'] });
  });

  test('Proofpoint URL Defense v2 and v3', () => {
    assert.equal(
      unwrap('https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.xyz_login-3Fid-3D1&d=DwMFaQ').url,
      'https://evil.xyz/login?id=1',
    );
    assert.equal(unwrap('https://urldefense.com/v3/__https://example.com/a__;!!AbC$').url, 'https://example.com/a');
    assert.equal(unwrap('https://urldefense.com/v3/__https://example.com/a*b__;Iw!!AbC$').via.length, 0,
      'v3 with substituted characters cannot be decoded, so stay on the wrapper');
  });

  test('nested wrappers are peeled in order, up to the hop limit', () => {
    const inner = 'https://www.google.com/url?q=https://evil.xyz';
    const outer = `https://nam12.safelinks.protection.outlook.com/?url=${encodeURIComponent(inner)}`;
    assert.deepEqual(unwrap(outer), { url: 'https://evil.xyz/', via: ['nam12.safelinks.protection.outlook.com', 'www.google.com'] });

    let url = 'https://evil.xyz/';
    for (let i = 0; i < MAX_REDIRECT_HOPS + 2; i++) url = `https://www.google.com/url?q=${encodeURIComponent(url)}`;
    assert.equal(unwrap(url).via.length, MAX_REDIRECT_HOPS);
  });

  test('only http(s) destinations are accepted', () => {
    assert.equal(unwrap('https://www.google.com/url?q=javascript:alert(1)').via.length, 0);
    assert.equal(unwrap('https://www.google.com/url?q=not-a-url').via.length, 0);
  });
});
