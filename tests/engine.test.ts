import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile, writeFile, readdir } from 'node:fs/promises';
import { setup, offlineOsv, updateVersion, projectZip, directAdvisory } from './helpers.js';
import { dependencyPaths, parseLockfile } from '../src/dependency/lockfile.js';
import { affectedBy } from '../src/vulnerability/matching.js';
import { buildFindings } from '../src/vulnerability/findings.js';
import { remediationFor, compareScans } from '../src/remediation/plan.js';
import { emptyMetrics } from '../src/engine/scanner.js';

test('end-to-end repository scan: direct, transitive, safe, reachable and unknown', async () => {
  const env = await setup();
  try {
    const scan = await env.scanner.scan(env.repository, 'repository');
    assert.equal(scan.graph.nodes.length, 4); assert.equal(scan.findings.length, 2); assert.equal(scan.vulnerability_status, 'complete');
    const direct = scan.findings.find(f => f.direct)!;
    assert.equal(direct.reachability.status, 'REACHABLE'); assert.ok(direct.reachability.evidence.some(e => e.line === 4));
    assert.equal(scan.findings.find(f => !f.direct)!.reachability.status, 'UNKNOWN');
    assert.ok(!scan.findings.some(f => f.package_name.endsWith('safe')));
    const transitive = scan.graph.nodes.find(n => n.name.endsWith('transitive'))!;
    assert.deepEqual(dependencyPaths(scan.graph, transitive.id).paths, [['root', 'node_modules/traceguard-test-parent', transitive.id]]);
  } finally { await env.cleanup(); }
});
test('ZIP scan matches repository and cleans extraction directories', async () => {
  const env = await setup();
  try {
    const archive = path.join(env.directory, 'project.zip'); await projectZip(env.repository, archive);
    const scan = await env.scanner.scan(archive, 'zip'); assert.equal(scan.findings.length, 2);
    assert.deepEqual(await readdir(path.join(env.scanner.settings.dataDir, 'temporary')), []);
    const snippet = await env.scanner.snippet(scan, 'src/index.js', 3, 3);
    assert.ok(!snippet.code.includes('TEST_SECRET')); assert.ok(snippet.code.includes('execute'));
    assert.deepEqual(await readdir(path.join(env.scanner.settings.dataDir, 'temporary')), []);
  } finally { await env.cleanup(); }
});
test('SBOM contains resolved versions, unique component refs and valid dependency refs', async () => {
  const env = await setup();
  try {
    const scan = await env.scanner.scan(env.repository, 'repository'); const generated = await env.scanner.sbom(scan);
    const bom = JSON.parse(await readFile(generated.artifact_path, 'utf8'));
    assert.equal(bom.bomFormat, 'CycloneDX'); assert.equal(bom.specVersion, '1.5'); assert.equal(bom.components.length, 4);
    const refs = new Set(['root', ...bom.components.map((c: any) => c['bom-ref'])]);
    assert.equal(refs.size, 5); assert.ok(bom.dependencies.every((d: any) => refs.has(d.ref) && d.dependsOn.every((ref: string) => refs.has(ref))));
    const before = scan.metrics.cache_hits; await env.scanner.sbom(scan); assert.ok(scan.metrics.cache_hits > before);
  } finally { await env.cleanup(); }
});
test('lockfile v1 nested resolution and v2/v3 hoisted resolution', () => {
  const manifest = { name: 'test', dependencies: { parent: '^1.0.0', child: '2.0.0' } };
  const v1 = parseLockfile(manifest, { lockfileVersion: 1, dependencies: { parent: { version: '1.0.0', requires: { child: '1.0.0' }, dependencies: { child: { version: '1.0.0' } } }, child: { version: '2.0.0' } } }, 'test');
  assert.deepEqual(v1.nodes.find(n => n.name === 'parent')!.children, ['node_modules/parent/node_modules/child']);
  assert.equal(v1.nodes.length, 3);
  const v2 = parseLockfile(manifest, { lockfileVersion: 2, packages: { '': {}, 'node_modules/parent': { version: '1.0.0', dependencies: { child: '*' } }, 'node_modules/child': { version: '2.0.0' } } }, 'test');
  assert.equal(v2.nodes.find(n => n.name === 'child')!.parents.length, 2);
  assert.throws(() => parseLockfile({}, { lockfileVersion: 4 }, 'test'), /lockfileVersion/);
  assert.throws(() => parseLockfile({}, { lockfileVersion: 3, packages: { '../escape': { version: '1.0.0' } } }, 'test'), /Unsafe/);
});
test('OSV SEMVER intervals, inclusive last_affected, unsupported ranges and prereleases', () => {
  const make = (events: any[]) => ({ package: { name: 'test', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events }] });
  const range = make([{ introduced: '0' }, { fixed: '1.2.0' }, { introduced: '2.0.0' }, { fixed: '2.1.0' }]);
  assert.equal(affectedBy('1.0.0', range), true); assert.equal(affectedBy('1.2.0', range), false);
  assert.equal(affectedBy('2.0.1', range), true); assert.equal(affectedBy('2.1.0', range), false);
  assert.equal(affectedBy('1.2.0-beta.1', range), true);
  assert.equal(affectedBy('1.2.0', make([{ introduced: '1.0.0' }, { last_affected: '1.2.0' }])), true);
  assert.equal(affectedBy('1.2.1', make([{ introduced: '1.0.0' }, { last_affected: '1.2.0' }])), false);
  assert.equal(affectedBy('1.0.0', { package: range.package, ranges: [{ type: 'GIT', events: [{ introduced: 'abc' }] }] }), undefined);
});
test('OSV pagination, rate limit retries, alias deduplication and warm cache', async () => {
  const alias = { ...directAdvisory, id: 'TRACEGUARD-TEST-SECOND', aliases: ['TRACEGUARD-TEST-ALIAS'] };
  const fake = offlineOsv({ paginate: true, rateLimit: true, records: [directAdvisory, alias] }); const env = await setup(fake.fetcher);
  try {
    const scan = await env.scanner.scan(env.repository, 'repository'); assert.equal(scan.findings.length, 1); assert.equal(scan.findings[0].advisory_ids.length, 2);
    assert.ok(fake.calls.some(c => c.body?.queries.some((q: any) => q.page_token)));
    const before = fake.calls.length; const again = await env.scanner.scan(env.repository, 'repository');
    assert.equal(fake.calls.length, before); assert.equal(again.metrics.static_files_reused, 1); assert.ok(again.metrics.cache_hits >= 5);
    assert.equal(buildFindings(scan.graph, { advisories: new Map(), unchecked: [], warnings: [] }).length, 0);
  } finally { await env.cleanup(); }
});
test('incremental source analysis and dependency invalidation', async () => {
  const env = await setup();
  try {
    const first = await env.scanner.scan(env.repository, 'repository');
    await writeFile(path.join(env.repository, 'src/other.js'), 'const value = 1;');
    const second = await env.scanner.scan(env.repository, 'repository');
    assert.equal(second.metrics.static_files_reused, 1); assert.equal(second.metrics.static_files_analyzed, 1); assert.notEqual(first.fingerprint, second.fingerprint);
    await updateVersion(env.repository, 'traceguard-test-direct', '1.0.1');
    const third = await env.scanner.scan(env.repository, 'repository'); assert.equal(third.findings.length, 1); assert.notEqual(second.graph.lockfile_hash, third.graph.lockfile_hash);
  } finally { await env.cleanup(); }
});
test('remediation verifies advisory-fixed candidates and fix comparison separates outcomes', async () => {
  const env = await setup();
  try {
    const first = await env.scanner.scan(env.repository, 'repository'); const direct = first.findings.find(f => f.direct)!;
    const item = await remediationFor(direct, env.scanner.osv, emptyMetrics());
    assert.equal(item.verified_unaffected_version, '1.0.1'); assert.match(item.recommended_command!, /--ignore-scripts --save-exact/);
    const transitive = await remediationFor(first.findings.find(f => !f.direct)!, env.scanner.osv, emptyMetrics());
    assert.equal(transitive.recommended_command, undefined);
    await updateVersion(env.repository, direct.package_name, '1.0.1');
    const second = await env.scanner.scan(env.repository, 'repository', true); const comparison = compareScans(first, second);
    assert.deepEqual(comparison.resolved_findings, [direct.id]); assert.equal(comparison.remaining_findings.length, 1); assert.equal(comparison.newly_detected_findings.length, 0);
    const unverified = compareScans(first, { ...second, vulnerability_status: 'unavailable' }); assert.deepEqual(unverified.unverified_findings, [direct.id]);
    const newlyDetected = compareScans(second, first); assert.deepEqual(newlyDetected.newly_detected_findings, [direct.id]);
  } finally { await env.cleanup(); }
});
test('OSV failure produces unavailable status and no fabricated findings', async () => {
  const env = await setup(offlineOsv({ fail: true }).fetcher);
  try {
    const scan = await env.scanner.scan(env.repository, 'repository');
    assert.equal(scan.vulnerability_status, 'unavailable'); assert.equal(scan.findings.length, 0); assert.equal(scan.unchecked_packages.length, 4);
  } finally { await env.cleanup(); }
});
test('source evidence refuses stale files and masks literals/comments', async () => {
  const env = await setup();
  try {
    const scan = await env.scanner.scan(env.repository, 'repository');
    const snippet = await env.scanner.snippet(scan, 'src/index.js', 1, 10); assert.ok(!snippet.code.includes('TEST_SECRET')); assert.ok(!snippet.code.includes('OFFLINE TEST DATA'));
    await writeFile(path.join(env.repository, 'src/index.js'), 'run();');
    await assert.rejects(env.scanner.snippet(scan, 'src/index.js', 1), /changed/);
    await assert.rejects(env.scanner.snippet(scan, '../secrets', 1), /not part/);
  } finally { await env.cleanup(); }
});
