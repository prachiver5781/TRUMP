import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile, writeFile, readdir, symlink } from 'node:fs/promises';
import { setup, makeZip, projectZip } from './helpers.js';
import { validateZipEntry } from '../src/engine/zip.js';
import { loadSettings } from '../src/server/config.js';
import { CacheStore } from '../src/cache/store.js';
import { emptyMetrics } from '../src/engine/scanner.js';
import { within } from '../src/utils/paths.js';

test('authorization is fail-closed and uses resolved path boundaries', async () => {
  assert.throws(() => loadSettings({}), /nonempty JSON/); assert.throws(() => loadSettings({ TRACEGUARD_ALLOWED_ROOTS: '["relative"]' }), /absolute/);
  assert.equal(within(path.resolve('allowed'), path.resolve('allowed-evil')), false);
  const env = await setup();
  try {
    await assert.rejects(env.scanner.scan(path.dirname(env.directory), 'repository'), /outside authorized/);
    await assert.rejects(env.scanner.scan('relative', 'repository'), /absolute/);
    await assert.rejects(env.scanner.scan(env.repository + '\0', 'repository'), /absolute/);
    const link = path.join(env.directory, 'escape');
    await symlink(path.dirname(env.directory), link, process.platform === 'win32' ? 'junction' : 'dir');
    await assert.rejects(env.scanner.scan(link, 'repository'), /outside authorized/);
  } finally { await env.cleanup(); }
});
test('ZIP path validator rejects traversal, Windows devices, drives, streams and ambiguous paths', () => {
  for (const name of ['../evil', '/absolute', 'C:/evil', 'a\\b', 'a/../b', 'a//b', 'a:stream', 'nul.txt', 'a/COM1.js', 'a/trailing.', 'a/trailing ', 'a\0x']) {
    assert.throws(() => validateZipEntry(name), /ZIP entry/);
  }
  validateZipEntry('project/src/index.js'); validateZipEntry('project/');
});
test('actual malicious ZIP traversal and symlink entries are rejected and cleaned', async () => {
  const env = await setup();
  try {
    const archive = path.join(env.directory, 'evil.zip'); await makeZip(archive, [{ name: 'xx/evil.js', value: 'evil' }]);
    const bytes = await readFile(archive); await writeFile(archive, Buffer.from(bytes.toString('latin1').replaceAll('xx/evil.js', '../evil.js'), 'latin1'));
    await assert.rejects(env.scanner.scan(archive, 'zip'), /ZIP/);
    await makeZip(archive, [{ name: 'link', value: '../../outside', mode: 0o120777 }]);
    await assert.rejects(env.scanner.scan(archive, 'zip'), /links/);
    assert.deepEqual(await readdir(path.join(env.scanner.settings.dataDir, 'temporary')), []);
  } finally { await env.cleanup(); }
});
test('ZIP rejects duplicate/case-colliding files and enforces entry and size limits', async () => {
  const env = await setup();
  try {
    const archive = path.join(env.directory, 'limits.zip');
    await makeZip(archive, [{ name: 'file.js', value: 'one' }, { name: 'FILE.js', value: 'two' }]);
    await assert.rejects(env.scanner.scan(archive, 'zip'), /colliding/);
    await makeZip(archive, [{ name: 'file.js', value: 'x'.repeat(1024) }]);
    env.scanner.settings.maxFileBytes = 100; await assert.rejects(env.scanner.scan(archive, 'zip'), /size limits/);
    env.scanner.settings.maxFileBytes = 10000; env.scanner.settings.maxFiles = 1;
    await makeZip(archive, [{ name: 'one.js', value: 'one' }, { name: 'two.js', value: 'two' }]);
    await assert.rejects(env.scanner.scan(archive, 'zip'), /entry-count/);
    env.scanner.settings.maxFiles = 1000; env.scanner.settings.maxArchiveBytes = 1;
    await assert.rejects(env.scanner.scan(archive, 'zip'), /compressed size/);
    assert.deepEqual(await readdir(path.join(env.scanner.settings.dataDir, 'temporary')), []);
  } finally { await env.cleanup(); }
});
test('repository enforces file and dependency limits without executing package scripts', async () => {
  const env = await setup();
  try {
    const manifestPath = path.join(env.repository, 'package.json');
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8')); manifest.scripts = { preinstall: 'THIS MUST NEVER EXECUTE' };
    await writeFile(manifestPath, JSON.stringify(manifest));
    const original = await readFile(manifestPath, 'utf8'); await env.scanner.scan(env.repository, 'repository'); assert.equal(await readFile(manifestPath, 'utf8'), original);
    env.scanner.settings.maxDependencies = 1;
    await assert.rejects(env.scanner.scan(env.repository, 'repository', true), /Too many/);
    env.scanner.settings.maxDependencies = 100; env.scanner.settings.maxFiles = 1;
    await assert.rejects(env.scanner.scan(env.repository, 'repository', true), /file-count/);
  } finally { await env.cleanup(); }
});
test('cache TTL, explicit invalidation and corrupt-cache recovery', async () => {
  const env = await setup();
  try {
    const cache = new CacheStore(path.join(env.directory, 'cache-test')); await cache.initialize(); const metrics = emptyMetrics();
    await cache.set('test', 'key', { n: 1 }, 60000); assert.deepEqual(await cache.get('test', 'key', metrics), { n: 1 });
    await cache.invalidate('test', 'key'); assert.equal(await cache.get('test', 'key', metrics), undefined);
    await cache.set('test', 'expired', { n: 2 }, -1); assert.equal(await cache.get('test', 'expired', metrics), undefined);
    await cache.set('test', 'corrupt', { n: 3 }, 60000);
    const files = await readdir(path.join(env.directory, 'cache-test')); await writeFile(path.join(env.directory, 'cache-test', files[0]), 'not json');
    assert.equal(await cache.get('test', 'corrupt', metrics), undefined); assert.equal(metrics.cache_hits, 1); assert.equal(metrics.cache_misses, 3);
  } finally { await env.cleanup(); }
});
test('incomplete archive layout fails without leaking extraction directories', async () => {
  const env = await setup();
  try {
    const archive = path.join(env.directory, 'incomplete.zip'); await makeZip(archive, [{ name: 'readme.txt', value: 'not a project' }]);
    await assert.rejects(env.scanner.scan(archive, 'zip'), /one npm project/);
    assert.deepEqual(await readdir(path.join(env.scanner.settings.dataDir, 'temporary')), []);
    await projectZip(env.repository, archive); const scan = await env.scanner.scan(archive, 'zip'); assert.equal(scan.graph.nodes.length, 4);
  } finally { await env.cleanup(); }
});
