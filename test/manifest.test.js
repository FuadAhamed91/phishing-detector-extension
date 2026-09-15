import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';

const manifest = JSON.parse(readFileSync(new URL('../manifest.json', import.meta.url), 'utf8'));
const exists = (file) => existsSync(new URL(`../${file}`, import.meta.url));

test('is Manifest V3 with a module service worker', () => {
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.background.type, 'module', 'background.js uses import');
});

test('every referenced file exists', () => {
  assert.ok(exists(manifest.background.service_worker));
  for (const cs of manifest.content_scripts) {
    for (const file of [...(cs.js || []), ...(cs.css || [])]) {
      assert.ok(exists(file), `${file} is missing`);
    }
  }
});

test('content scripts run on every page', () => {
  assert.deepEqual(manifest.content_scripts[0].matches, ['<all_urls>']);
});
