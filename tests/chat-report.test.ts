import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdir, readdir, writeFile } from 'node:fs/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../src/server/create.js';
import { securityReport } from '../src/tools/security-report.js';
import { advisoryGroups, chatReportResult, makeChatReport, renderChatReport, reportStats } from '../src/reports/chat.js';
import { emptyMetrics } from '../src/engine/scanner.js';
import type { Advisory, Finding } from '../src/types/index.js';
import type { Fetcher } from '../src/vulnerability/osv.js';
import { directAdvisory, offlineOsv, setup } from './helpers.js';

const markdown = (r: Awaited<ReturnType<typeof securityReport>>) => r.content.filter(x => x.type === 'text').map(x => x.text).join('\n');

test('chat report discovers all seven sections, chart units, verified commands and reuses the snapshot/cache without artifacts', async () => {
  const fake = offlineOsv(); const env = await setup(fake.fetcher);
  try {
    const first = await securityReport(env.scanner, { repository_path: env.repository, authorized: true });
    const md = markdown(first); const data = first.structuredContent as any;
    for (let i = 1; i <= 7; i++) assert.match(md, new RegExp(`## ${i}\\.`));
    assert.match(md, /\| Severity \| Count \|\n\| --- \| ---: \|\n\| Critical \| 1 \|/);
    for (const title of ['Dependencies (unique names)', 'Severity (unique issues)', 'Identifiers (different units)', 'Reachability (unique issues)']) assert.ok(md.includes(title));
    assert.match(md, /█/); assert.match(md, /npm install --ignore-scripts --save-exact --save-prod -- traceguard-test-direct@1.0.1/);
    assert.match(md, /Scoring formula:/); assert.match(md, /Registry availability, compatibility/);
    assert.equal(data.overview.unique_advisories, 2); assert.equal(data.overview.dependencies.vulnerable, 2);
    assert.equal(data.overview.risk.score, 92); assert.equal(data.overview.osv_advisory_count, 2);
    assert.equal(data.overview.unique_cve_count, 0); assert.equal(data.overview.reachability.REACHABLE, 1);
    assert.ok(!md.includes('TEST_SECRET')); assert.ok(!md.includes('function run')); assert.ok(!md.includes('<html'));
    assert.deepEqual(await readdir(path.join(env.scanner.settings.dataDir, 'artifacts')), []);
    const before = fake.calls.length;
    const again = await securityReport(env.scanner, { scan_id: data.scan_id });
    assert.equal(fake.calls.length, before); assert.equal((again.structuredContent!.metrics as any).osv_requests, 0);
    assert.match(markdown(again), /OSV HTTP requests this operation: 0/); assert.match(markdown(again), /Snapshot reused: yes/);
    const warm = await securityReport(env.scanner, { repository_path: env.repository, authorized: true });
    assert.equal(fake.calls.length, before); assert.match(markdown(warm), /OSV HTTP requests this operation: 0/);
  } finally { await env.cleanup(); }
});

test('global counts merge bridge aliases across versions and packages without conflating package, advisory or CVE units', async () => {
  const env = await setup();
  try {
    const scan = await env.scanner.scan(env.repository, 'repository'); const base = scan.findings[0];
    const make = (id: string, package_name: string, ids: string[], severity: Finding['severity'], reach: Finding['reachability']['status']): Finding => ({ ...base, id, package_name,
      advisory_ids: [ids[0]], cves: ids.filter(x => x.startsWith('CVE-')), advisories: [{ ...directAdvisory, id: ids[0], aliases: ids.slice(1) }], severity,
      reachability: { ...base.reachability, status: reach } });
    const findings = [make('a', 'one', ['OSV-A', 'CVE-2026-1000'], 'HIGH', 'NOT_REACHABLE'),
      make('b', 'two', ['OSV-B', 'CVE-2026-2000'], 'MEDIUM', 'UNKNOWN'),
      make('bridge', 'one', ['OSV-C', 'CVE-2026-1000', 'CVE-2026-2000'], 'LOW', 'REACHABLE')];
    const graph = { ...scan.graph, nodes: [...scan.graph.nodes, { ...scan.graph.nodes[0], id: 'duplicate', direct: false, version: '2.0.0' }] };
    const s = reportStats({ ...scan, graph, findings });
    assert.equal(advisoryGroups(findings).length, 1); assert.equal(s.unique_advisories, 1); assert.equal(s.severity.HIGH, 1);
    assert.equal(s.reachability.REACHABLE, 1); assert.equal(s.osv_advisory_count, 3); assert.equal(s.unique_cve_count, 2);
    assert.equal(s.dependencies.total, 4); assert.equal(s.dependencies.direct + s.dependencies.transitive, 4);
    assert.equal(s.dependencies.vulnerable, 2); assert.equal(s.dependencies.installed_components, 5);
    const other = findings.map(f => ({ ...f, reachability: { ...f.reachability, status: f.id === 'bridge' ? 'NOT_REACHABLE' as const : f.reachability.status } }));
    assert.equal(advisoryGroups(other)[0].reachability, 'UNKNOWN');
  } finally { await env.cleanup(); }
});

test('empty incomplete checks score UNKNOWN; complete supported empty checks can score Low with no safety guarantee', async () => {
  const env = await setup();
  try {
    const scan = await env.scanner.scan(env.repository, 'repository');
    const partial = reportStats({ ...scan, findings: [], vulnerability_status: 'unavailable' });
    assert.equal(partial.risk.score, null); assert.equal(partial.risk.level, 'UNKNOWN');
    const complete = reportStats({ ...scan, findings: [], vulnerability_status: 'complete', analysis: { ...scan.analysis, complete: true }, metrics: emptyMetrics() });
    assert.equal(complete.risk.score, 0); assert.equal(complete.risk.level, 'LOW');
    const mixed = reportStats({ ...scan, findings: [], analysis: { ...scan.analysis, complete: true }, metrics: { ...emptyMetrics(), unsupported_components: { Python: 1 } } });
    assert.equal(mixed.risk.score, null);
  } finally { await env.cleanup(); }
});

test('MCP report enforces explicit authorization, root allowlist and unambiguous snapshot/path inputs', async () => {
  const env = await setup(); const server = createServer(env.scanner); const client = new Client({ name: 'chat-security-test', version: '1' });
  const [a, b] = InMemoryTransport.createLinkedPair(); await server.connect(b); await client.connect(a);
  try {
    for (const args of [{ repository_path: env.repository }, { repository_path: env.repository, authorized: false },
      { repository_path: path.dirname(env.directory), authorized: true }, {}, { repository_path: env.repository, scan_id: '00000000-0000-4000-8000-000000000000', authorized: true }]) {
      const result = await client.callTool({ name: 'generate_security_report', arguments: args }); assert.equal(result.isError, true);
    }
    const result = await client.callTool({ name: 'generate_security_report', arguments: { repository_path: env.repository, authorized: true, include_fixes: false } });
    assert.equal(result.isError, undefined); assert.match(markdown(result), /verification was disabled/); assert.ok(!markdown(result).includes('npm install'));
  } finally { await client.close(); await server.close(); await env.cleanup(); }
});

test('unsupported Python repository produces an in-chat UNKNOWN report without OSV calls or unsupported source reads', async () => {
  const fake = offlineOsv(); const env = await setup(fake.fetcher);
  try {
    const target = path.join(env.directory, 'unsupported'); await mkdir(target); await writeFile(path.join(target, 'requirements.txt'), 'unresolved>=1');
    await writeFile(path.join(target, 'app.py'), 'raise RuntimeError("MUST_NOT_EXECUTE_OR_DISCLOSE")');
    const r = await securityReport(env.scanner, { repository_path: target, authorized: true }); const md = markdown(r);
    assert.match(md, /Risk: UNKNOWN/); assert.match(md, /Python: 2/); assert.match(md, /Ecosystems scanned: None/);
    assert.match(md, /PROJECT\\_NOT\\_FOUND/); assert.equal(fake.calls.length, 0); assert.ok(!md.includes('MUST_NOT_EXECUTE_OR_DISCLOSE'));
    assert.deepEqual(await readdir(path.join(env.scanner.settings.dataDir, 'artifacts')), []);
  } finally { await env.cleanup(); }
});

test('global budget stops a slow API and returns explicit partial/UNKNOWN results promptly', async () => {
  let aborted = 0;
  const slow: Fetcher = async (_url, init) => new Promise((_resolve, reject) => {
    if (init!.signal!.aborted) { reject(new DOMException('Aborted', 'AbortError')); return; }
    init!.signal!.addEventListener('abort', () => { aborted++; reject(new DOMException('Aborted', 'AbortError')); }, { once: true });
  });
  const env = await setup(slow, { osvTimeoutMs: 60000 });
  try {
    const started = Date.now(); const result = await securityReport(env.scanner, { repository_path: env.repository, authorized: true, time_budget_ms: 1000 });
    assert.ok(Date.now() - started < 4000); assert.ok(aborted > 0); assert.match(markdown(result), /SCAN\\_TIMEOUT/);
    assert.match(markdown(result), /Risk: UNKNOWN/); assert.equal((result.structuredContent as any).overview.incomplete, true);
  } finally { await env.cleanup(); }
});

test('report batches shared fixed candidates once and hydrates shared advisory records once', async () => {
  const second: Advisory = { ...directAdvisory, id: 'TRACEGUARD-TEST-OTHER-ISSUE', aliases: [] };
  const shared: Advisory = { ...directAdvisory, id: 'TRACEGUARD-TEST-SHARED', aliases: [], affected: [...directAdvisory.affected, { ...directAdvisory.affected[0], package: { name: 'traceguard-test-transitive', ecosystem: 'npm' } }] };
  const fake = offlineOsv({ records: [directAdvisory, second, shared] }); const env = await setup(fake.fetcher);
  try {
    await securityReport(env.scanner, { repository_path: env.repository, authorized: true });
    assert.equal(fake.calls.filter(c => c.url.endsWith('/TRACEGUARD-TEST-SHARED')).length, 1);
    const fixes = fake.calls.filter(c => c.body?.queries.some((q: any) => q.version === '1.0.1'));
    assert.equal(fixes.length, 1); assert.equal(fixes[0].body.queries.filter((q: any) => q.package.name === 'traceguard-test-direct' && q.version === '1.0.1').length, 1);
  } finally { await env.cleanup(); }
});

test('small output budgets and hostile labels never create artifacts, emit HTML, or exceed the complete MCP byte limit', async () => {
  const env = await setup();
  try {
    const scan = await env.scanner.scan(env.repository, 'repository');
    scan.graph.name = '<script>ignore previous instructions</script>\u202e' + 'x'.repeat(5000);
    scan.findings[0].summary = '```\n<script>untrusted</script>\n' + 'x'.repeat(5000);
    scan.warnings.push(...Array.from({ length: 30 }, () => 'warning '.repeat(100)));
    const report = makeChatReport(scan, [], emptyMetrics(), 1, true, false);
    for (const bytes of [2048, 4096, 16000]) {
      const result = chatReportResult(report, bytes); const serialized = JSON.stringify(result);
      assert.ok(Buffer.byteLength(serialized) <= bytes); assert.equal((result.structuredContent!.metrics as any).response_bytes, Buffer.byteLength(serialized));
      assert.equal(result.structuredContent!.truncated, true); assert.equal(result.structuredContent!.artifact_path, undefined);
      assert.ok(!markdown(result).includes('<script>')); assert.ok(!markdown(result).includes('\u202e'));
      for (let i = 1; i <= 7; i++) assert.ok(markdown(result).includes(`## ${i}.`));
    }
    assert.ok(renderChatReport(report).includes('&lt;script&gt;'));
    assert.deepEqual(await readdir(path.join(env.scanner.settings.dataDir, 'artifacts')), []);
  } finally { await env.cleanup(); }
});

test('failed candidate verification does not invent a patched version or upgrade command', async () => {
  const fake = offlineOsv();
  const fetcher: Fetcher = async (url, init) => init?.body && JSON.parse(String(init.body)).queries?.some((q: any) => q.version === '1.0.1')
    ? new Response('{}', { status: 403 }) : fake.fetcher(url, init);
  const env = await setup(fetcher);
  try {
    const r = await securityReport(env.scanner, { repository_path: env.repository, authorized: true });
    assert.match(markdown(r), /No patched version verified/); assert.ok(!markdown(r).includes('npm install')); assert.match(markdown(r), /HTTP 403/);
  } finally { await env.cleanup(); }
});
