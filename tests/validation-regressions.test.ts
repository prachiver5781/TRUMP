import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readdir, writeFile } from 'node:fs/promises';
import { setup, offlineOsv, directAdvisory } from './helpers.js';
import { CacheStore } from '../src/cache/store.js';
import { affectedBy, advisorySeverity } from '../src/vulnerability/matching.js';
import { parseLockfile } from '../src/dependency/lockfile.js';
import { Output } from '../src/utils/output.js';

test('side-effect CommonJS require contributes a local module execution edge', async () => {
  const env = await setup();
  try {
    await writeFile(path.join(env.repository, 'src/index.js'), "require('./worker.js');");
    await writeFile(path.join(env.repository, 'src/worker.js'), "const { dangerous } = require('traceguard-test-direct'); dangerous();");
    const scan = await env.scanner.scan(env.repository, 'repository');
    assert.equal(scan.findings.find(f => f.direct)!.reachability.status, 'REACHABLE');
  } finally { await env.cleanup(); }
});
test('unsupported inline require and indirect invocation cannot give a negative reachability result', async () => {
  const env = await setup();
  try {
    for (const source of ["require('traceguard-test-direct').dangerous();", "import { dangerous } from 'traceguard-test-direct'; dangerous.call(null);", "import { dangerous } from 'traceguard-test-direct'; dangerous.apply(null, []);"]) {
      await writeFile(path.join(env.repository, 'src/index.js'), source);
      const scan = await env.scanner.scan(env.repository, 'repository');
      assert.equal(scan.findings.find(f => f.direct)!.reachability.status, 'UNKNOWN', source);
    }
  } finally { await env.cleanup(); }
});
test('unmodeled calls inside the vulnerable package cannot establish NOT_REACHABLE', async () => {
  const env = await setup();
  try {
    await writeFile(path.join(env.repository, 'src/index.js'), "import { wrapper } from 'traceguard-test-direct'; wrapper();");
    const scan = await env.scanner.scan(env.repository, 'repository');
    assert.equal(scan.findings.find(f => f.direct)!.reachability.status, 'UNKNOWN');
  } finally { await env.cleanup(); }
});
test('malformed cache envelope is a miss rather than an immortal cache entry', async () => {
  const env = await setup();
  try {
    const directory = path.join(env.directory, 'corrupt-cache'); const cache = new CacheStore(directory); await cache.initialize();
    await cache.set('test', 'entry', { trusted: true }, 60000);
    const filename = path.join(directory, (await readdir(directory))[0]);
    for (const value of [{ value: { trusted: false } }, { expires: 'forever', value: {} }, { expires: Date.now() + 60000 }]) {
      await writeFile(filename, JSON.stringify(value)); assert.equal(await cache.get('test', 'entry'), undefined);
    }
  } finally { await env.cleanup(); }
});
test('partial advisory hydration retains known vulnerability evidence', async () => {
  const invalid = { ...directAdvisory, id: 'TRACEGUARD-TEST-MALFORMED', aliases: [], database_specific: { severity: 42 } } as any;
  const env = await setup(offlineOsv({ records: [directAdvisory, invalid] }).fetcher);
  try {
    const scan = await env.scanner.scan(env.repository, 'repository');
    assert.equal(scan.vulnerability_status, 'partial'); assert.ok(scan.findings.some(f => f.advisory_ids.includes(directAdvisory.id)));
    assert.ok(scan.unchecked_packages.includes('traceguard-test-direct@1.0.0'));
  } finally { await env.cleanup(); }
});
test('malformed affected ranges and impossible severity scores are treated as unknown', () => {
  assert.equal(affectedBy('1.0.0', { package: { name: 'test', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ fixed: '2.0.0' }] }] }), undefined);
  assert.equal(advisorySeverity([{ ...directAdvisory, database_specific: {}, severity: [{ type: 'CVSS_V3', score: '99' }] }]), 'UNKNOWN');
});
test('invalid manifest and packages table cannot produce a complete empty graph', async () => {
  assert.throws(() => parseLockfile(null, { lockfileVersion: 3, packages: {} }, 'hash'), /object/);
  assert.throws(() => parseLockfile({}, { lockfileVersion: 3, packages: [] }, 'hash'), /packages/);
  const env = await setup();
  try {
    await writeFile(path.join(env.repository, 'package.json'), '[]');
    await assert.rejects(env.scanner.scan(env.repository, 'repository'), /object/);
  } finally { await env.cleanup(); }
});
test('malformed OSV cache content is re-queried instead of producing a false clean result', async () => {
  const fake = offlineOsv(); const env = await setup(fake.fetcher);
  try {
    await env.scanner.cache.set('osv-query-v3', 'traceguard-test-direct@1.0.0', { checked_at: new Date().toISOString(), invalid: true }, 60000);
    const scan = await env.scanner.scan(env.repository, 'repository'); assert.ok(scan.findings.some(f => f.direct)); assert.ok(fake.calls.length > 0);
  } finally { await env.cleanup(); }
});
test('oversized fallback metadata stays within the hard cap and long query scopes have usable cursors', async () => {
  const env = await setup(undefined, { maxOutputBytes: 2048 });
  try {
    const output = new Output(env.scanner); const scope = 'impact:' + 'nested-location/'.repeat(300);
    const cursor = output.cursor(scope, 3); assert.ok(cursor.length < 2048); assert.equal(output.offset(cursor, scope), 3);
    const response = await output.result({ risk_summary: 'x'.repeat(10000), items: [], truncated: false });
    assert.ok(Buffer.byteLength(JSON.stringify(response)) <= 2048); assert.equal(response.structuredContent!.truncated, true); assert.ok(response.structuredContent!.artifact_path);
  } finally { await env.cleanup(); }
});
test('actual OSV request counters distinguish cold, warm and forced scans', async () => {
  const fake = offlineOsv(); const env = await setup(fake.fetcher);
  try {
    const cold = await env.scanner.scan(env.repository, 'repository'); assert.equal(cold.metrics.osv_requests, fake.calls.length);
    const before = fake.calls.length; const warm = await env.scanner.scan(env.repository, 'repository');
    assert.equal(warm.metrics.osv_requests, 0); assert.equal(fake.calls.length, before);
    const forced = await env.scanner.scan(env.repository, 'repository', true); assert.equal(forced.metrics.osv_requests, fake.calls.length - before); assert.ok(forced.metrics.osv_requests > 0);
  } finally { await env.cleanup(); }
});
