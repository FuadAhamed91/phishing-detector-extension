import { test } from 'node:test';
import assert from 'node:assert/strict';

// background.js registers a chrome.runtime.onMessage listener at import time,
// so stub the chrome namespace before importing it.
let listener;
globalThis.chrome = {
  runtime: {
    onMessage: { addListener: (fn) => { listener = fn; } },
  },
};
await import('../background.js');

function send(message) {
  let response;
  const returned = listener(message, {}, (r) => { response = r; });
  return { response, returned };
}

test('registers exactly one onMessage listener', () => {
  assert.equal(typeof listener, 'function');
});

test('answers ANALYZE_URL synchronously with a score and status', () => {
  const { response, returned } = send({ type: 'ANALYZE_URL', url: 'https://github.com/' });
  assert.equal(returned, undefined, 'must not return true: the channel is not kept open');
  assert.equal(typeof response.score, 'number');
  assert.ok(['safe', 'warning'].includes(response.status));
});

test('ignores unrelated messages', () => {
  assert.equal(send({ type: 'SOMETHING_ELSE' }).response, undefined);
  assert.equal(send(null).response, undefined);
});
