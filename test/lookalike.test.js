import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { domainToASCII, domainToUnicode } from 'node:url';

import { punycodeDecode, decodeLabel, foldToAscii, tokenize, findBrandAbuse } from '../lookalike.js';

describe('punycode', () => {
  test('decodes labels exactly like Node\'s IDNA implementation', () => {
    for (const word of ['münchen', 'аррӏе', 'βόλος', '例子', 'pаypаl', 'bücher', 'ñandú', '日本語']) {
      const ascii = domainToASCII(`${word}.com`).replace(/\.com$/, '');
      const expected = domainToUnicode(`${ascii}.com`).replace(/\.com$/, '');
      assert.equal(decodeLabel(ascii), expected, ascii);
    }
  });

  test('leaves plain labels alone and falls back to the raw label on malformed input', () => {
    assert.equal(decodeLabel('example'), 'example');
    assert.equal(decodeLabel('xn--!!!'), 'xn--!!!');
    assert.throws(() => punycodeDecode('!!!'), RangeError);
  });
});

describe('foldToAscii', () => {
  test('strips accents and maps confusable letters onto Latin ones', () => {
    assert.equal(foldToAscii('münchen'), 'munchen');
    assert.equal(foldToAscii('аррӏе'), 'apple');   // Cyrillic
    assert.equal(foldToAscii('pаypаl'), 'paypal');  // mixed script
    assert.equal(foldToAscii('PAYPAL'), 'paypal');
  });

  test('leaves scripts with no Latin look-alikes untouched', () => {
    assert.equal(foldToAscii('例子'), '例子');
  });
});

describe('tokenize', () => {
  test('splits on dots, hyphens and anything non-alphanumeric', () => {
    assert.deepEqual(tokenize('paypal.com-secure'), ['paypal', 'com', 'secure']);
    assert.deepEqual(tokenize('例子'), []);
  });
});

describe('findBrandAbuse', () => {
  const abuse = (owned) => {
    const sld = owned.split('.').at(-1);
    const found = findBrandAbuse({ owned, sld });
    return found && `${found.kind}:${found.brand}:${found.token}`;
  };

  test('brand name on a domain the brand does not own', () => {
    assert.equal(abuse('paypal.com.evil'), 'impersonation:paypal:paypal');
    assert.equal(abuse('secure-paypal'), 'impersonation:paypal:paypal');
    assert.equal(abuse('paypalsupport'), 'impersonation:paypal:paypalsupport');
    assert.equal(abuse('wells-fargo-login'), 'impersonation:wellsfargo:wells-fargo-login');
    assert.equal(abuse('irs-refund'), 'impersonation:irs:irs');
  });

  test('the brand\'s own domains and its company family are fine', () => {
    assert.equal(abuse('www.paypalobjects'), null);
    assert.equal(abuse('itunes.apple'), null);
    assert.equal(abuse('outlook.office'), null);
    assert.equal(abuse('accounts.google'), null);
    assert.equal(abuse('amex.americanexpress'), null);
  });

  test('short brands only match as whole tokens', () => {
    assert.equal(abuse('pineapple'), null);
    assert.equal(abuse('purchase'), null);
    assert.equal(abuse('first'), null);
  });

  test('digits and letter pairs standing in for letters', () => {
    assert.equal(abuse('amaz0n'), 'lookalike:amazon:amaz0n');
    assert.equal(abuse('paypa1'), 'lookalike:paypal:paypa1');
    assert.equal(abuse('m1crosoft'), 'lookalike:microsoft:m1crosoft');
    assert.equal(abuse('rnicrosoft'), 'lookalike:microsoft:rnicrosoft');
  });

  test('foreign letters that look Latin are reported by their punycode label', () => {
    assert.equal(abuse('xn--80ak6aa92e'), 'lookalike:apple:xn--80ak6aa92e');
    assert.equal(abuse('xn--pypl-53dc'), 'lookalike:paypal:xn--pypl-53dc');
    assert.equal(findBrandAbuse({ owned: 'xn--80ak6aa92e', sld: 'xn--80ak6aa92e' }).idn, true);
  });

  test('one typo away from a longer brand', () => {
    assert.equal(abuse('googel'), 'lookalike:google:googel');
    assert.equal(abuse('linkedln'), 'lookalike:linkedin:linkedln');
    assert.equal(abuse('facebok'), 'lookalike:facebook:facebok');
    assert.equal(abuse('amazn.evil'), 'lookalike:amazon:amazn');
  });

  test('typo matching is off for short brands and for two-edit neighbours', () => {
    assert.equal(abuse('chose'), null);       // chase
    assert.equal(abuse('shopify'), null);     // spotify is two edits away
    assert.equal(abuse('telegraph'), null);   // telegram is two edits away
  });

  test('ordinary words near a brand are never flagged', () => {
    assert.equal(abuse('finance.yahoo'), null);   // binance
    assert.equal(abuse('cloud.google'), null);    // icloud
    assert.equal(abuse('amazonas.gov'), null);    // amazon
    assert.equal(abuse('papal-news'), null);      // paypal
  });

  test('nothing to inspect', () => {
    assert.equal(findBrandAbuse({ owned: '', sld: '' }), null);
  });
});
