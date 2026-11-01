import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { writeFile } from 'node:fs/promises';
import { setup, offlineOsv, directAdvisory, transitiveAdvisory, updateVersion } from './helpers.js';
import { remediationFor, compareScans } from '../src/remediation/plan.js';
import { emptyMetrics } from '../src/engine/scanner.js';
import { parseSource } from '../src/analysis/static.js';

test('properties and reassignment of local functions cannot fabricate a reachable call', async () => {
  const env = await setup();
  try {
    await writeFile(path.join(env.repository, 'src/index.js'), "import { dangerous } from 'traceguard-test-direct'; function run(){dangerous();} run.something();");
    const property = await env.scanner.scan(env.repository, 'repository'); assert.equal(property.findings.find(f => f.direct)!.reachability.status, 'UNKNOWN');
    await writeFile(path.join(env.repository, 'src/index.js'), "import { dangerous } from 'traceguard-test-direct'; function run(){dangerous();} run = () => {}; run();");
    const reassigned = await env.scanner.scan(env.repository, 'repository'); assert.equal(reassigned.findings.find(f => f.direct)!.reachability.status, 'UNKNOWN');
  } finally { await env.cleanup(); }
});
test('unknown relative exports do not yield false negative reachability', async () => {
  const env = await setup();
  try {
    await writeFile(path.join(env.repository, 'src/index.js'), "import run from './worker.js'; run();");
    await writeFile(path.join(env.repository, 'src/worker.js'), "import { dangerous } from 'traceguard-test-direct'; export default () => dangerous();");
    const scan = await env.scanner.scan(env.repository, 'repository'); assert.equal(scan.findings.find(f => f.direct)!.reachability.status, 'UNKNOWN');
  } finally { await env.cleanup(); }
});
test('malformed OSV advisory is unverified while other packages retain valid findings', async () => {
  const fake = offlineOsv({ records: [{ ...directAdvisory, database_specific: { severity: 42 } } as any, transitiveAdvisory] });
  const env = await setup(fake.fetcher);
  try {
    const scan = await env.scanner.scan(env.repository, 'repository'); assert.equal(scan.vulnerability_status, 'partial');
    assert.equal(scan.findings.length, 1); assert.equal(scan.findings[0].package_name, 'traceguard-test-transitive');
    assert.ok(scan.unchecked_packages.includes('traceguard-test-direct@1.0.0'));
  } finally { await env.cleanup(); }
});
test('a candidate that still falls in a known range is never recommended as unaffected', async () => {
  const overlap = { ...directAdvisory, affected: [...directAdvisory.affected, { package: { name: 'traceguard-test-direct', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }] };
  const env = await setup(offlineOsv({ records: [overlap] }).fetcher);
  try {
    const scan = await env.scanner.scan(env.repository, 'repository'); const plan = await remediationFor(scan.findings[0], env.scanner.osv, emptyMetrics());
    assert.equal(plan.verified_unaffected_version, '2.0.0'); assert.ok(!plan.recommended_command!.includes('@1.0.1'));
    const dev = await remediationFor(scan.findings[0], env.scanner.osv, emptyMetrics(), false, 'dev'); assert.match(dev.recommended_command!, /--save-dev -- /);
  } finally { await env.cleanup(); }
});
test('fix comparison tolerates newly added CVE aliases and repeated vulnerable versions', async () => {
  const env = await setup();
  try {
    const previous = await env.scanner.scan(env.repository, 'repository'); const direct = previous.findings.find(f => f.direct)!;
    const changed = structuredClone(previous); const finding = changed.findings.find(f => f.direct)!;
    finding.cves = ['CVE-0000-0001']; finding.advisories[0].aliases = [...finding.advisories[0].aliases!, 'CVE-0000-0001'];
    const result = compareScans(previous, changed); assert.equal(result.resolved_findings.length, 0); assert.equal(result.newly_detected_findings.length, 0);
    changed.findings.push({ ...finding, version: '0.9.0', id: 'another-installed-version' });
    assert.equal(compareScans(previous, changed).newly_detected_findings.length, 0); assert.ok(result.remaining_findings.includes(direct.id));
    await updateVersion(env.repository, direct.package_name, '1.0.1');
  } finally { await env.cleanup(); }
});
test('snippet masks template-literal tails, regex contents and multiline comments', async () => {
  const env = await setup();
  try {
    await writeFile(path.join(env.repository, 'src/index.js'), 'const name = "TEST_SECRET_1";\nconst token = `TEST_SECRET_2${name}TEST_SECRET_3`;\nconst regex = /TEST_SECRET_4/;\n/* TEST_SECRET_5 */\n');
    const scan = await env.scanner.scan(env.repository, 'repository'); const snippet = await env.scanner.snippet(scan, 'src/index.js', 1, 10);
    assert.ok(!snippet.code.includes('TEST_SECRET'), snippet.code); assert.equal(snippet.start_line, 1);
  } finally { await env.cleanup(); }
});
test('AST complexity limits fail explicitly rather than silently truncating calls', () => {
  assert.throws(() => parseSource('large.js', 'function run(){}\n' + 'run();\n'.repeat(20002)), /complexity limits/);
});
test('OSV timeout is bounded and never becomes a clean vulnerability check', async () => {
  let aborted = 0;
  const env = await setup(async (_input, init) => new Promise((_resolve, reject) => {
    init!.signal!.addEventListener('abort', () => { aborted++; reject(new Error('TEST timeout')); }, { once: true });
  }));
  try {
    const started = Date.now(); const scan = await env.scanner.scan(env.repository, 'repository');
    assert.equal(scan.vulnerability_status, 'unavailable'); assert.equal(aborted, 3); assert.ok(Date.now() - started < 5000);
  } finally { await env.cleanup(); }
});
