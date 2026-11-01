import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { createServer } from '../src/server/create.js';
import { Output } from '../src/utils/output.js';
import { setup, projectZip, projectDirectory, updateVersion } from './helpers.js';

test('MCP preserves the original tools and discovers the chat report with validated structured output', async () => {
  const env = await setup(); const server = createServer(env.scanner); const client = new Client({ name: 'traceguard-offline-test', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport); await client.connect(clientTransport);
  const call = async (name: string, args: Record<string, unknown>) => {
    const result = await client.callTool({ name, arguments: args }); assert.equal(result.isError, undefined, JSON.stringify(result));
    assert.ok(result.structuredContent); assert.ok(Buffer.byteLength(JSON.stringify(result)) <= env.scanner.settings.maxOutputBytes);
    return result.structuredContent as any;
  };
  try {
    assert.equal(client.getServerVersion()!.name, 'traceguard-mcp'); const tools = await client.listTools();
    const toolNames = new Set(tools.tools.map(t => t.name));
    for (const name of ['scan_repository', 'scan_zip', 'generate_sbom', 'check_vulnerabilities', 'get_dependency_graph', 'analyze_reachability', 'get_impact_analysis', 'generate_remediation_plan', 'verify_fixes', 'get_scan_summary', 'get_finding_details', 'generate_security_report']) assert.ok(toolNames.has(name), name);
    assert.ok(tools.tools.every(t => t.inputSchema && t.outputSchema && t.description));
    const invalid = await client.callTool({ name: 'scan_repository', arguments: { repository_path: env.repository, authorized: false } }); assert.equal(invalid.isError, true);
    const unauthorized = await client.callTool({ name: 'scan_repository', arguments: { repository_path: path.dirname(env.directory), authorized: true } }); assert.equal(unauthorized.isError, true);
    const scan = await call('scan_repository', { repository_path: env.repository, authorized: true });
    assert.equal(scan.total_dependencies, 4); assert.equal(scan.vulnerability_counts.CRITICAL, 1); assert.equal(scan.reachability_summary.REACHABLE, 1);
    assert.ok(!JSON.stringify(scan).includes('TEST_SECRET')); assert.ok(!JSON.stringify(scan).includes('function run'));
    const summary = await call('get_scan_summary', { scan_id: scan.scan_id }); assert.equal(summary.scan_id, scan.scan_id);
    const report = await call('generate_security_report', { scan_id: scan.scan_id }); assert.equal(report.overview.unique_advisories, 2);
    const findings = await call('check_vulnerabilities', { scan_id: scan.scan_id, page_size: 1 }); assert.equal(findings.items.length, 1); assert.equal(findings.truncated, true);
    const next = await call('check_vulnerabilities', { scan_id: scan.scan_id, page_size: 1, cursor: findings.next_cursor }); assert.equal(next.items.length, 1); assert.equal(next.truncated, false);
    assert.notEqual(findings.items[0].finding_id, next.items[0].finding_id);
    const badCursor = await client.callTool({ name: 'check_vulnerabilities', arguments: { scan_id: scan.scan_id, cursor: findings.next_cursor + 'x' } }); assert.equal(badCursor.isError, true);
    const graph = await call('get_dependency_graph', { scan_id: scan.scan_id, page_size: 2, mode: 'detailed' }); assert.equal(graph.returned_items, 2); assert.ok(graph.items[0].parents);
    const reach = await call('analyze_reachability', { scan_id: scan.scan_id }); assert.equal(reach.items[0].status, 'REACHABLE');
    const findingId = findings.items[0].finding_id;
    const paths = await call('analyze_reachability', { scan_id: scan.scan_id, finding_id: findingId, view: 'paths', page_size: 1 }); assert.equal(paths.items.length, 1);
    const impact = await call('get_impact_analysis', { scan_id: scan.scan_id, finding_id: findingId }); assert.ok(impact.items[0].includes('root'));
    const details = await call('get_finding_details', { scan_id: scan.scan_id, finding_id: findingId }); assert.ok(details.finding.advisories); assert.equal(details.snippet, undefined);
    const evidence = await call('get_finding_details', { scan_id: scan.scan_id, finding_id: findingId, include_snippet: true, evidence_index: 1 }); assert.ok(evidence.snippet.code); assert.ok(!evidence.snippet.code.includes('TEST_SECRET'));
    const sbom = await call('generate_sbom', { scan_id: scan.scan_id }); assert.equal(JSON.parse(await readFile(sbom.artifact_path, 'utf8')).components.length, 4);
    const plan = await call('generate_remediation_plan', { scan_id: scan.scan_id, page_size: 1 }); assert.equal(plan.items[0].verified_unaffected_version, '1.0.1'); assert.ok(plan.next_cursor);
    const secondPlan = await call('generate_remediation_plan', { scan_id: scan.scan_id, cursor: plan.next_cursor, page_size: 1 }); assert.equal(secondPlan.items.length, 1);
    const archive = path.join(env.directory, 'project.zip'); await projectZip(env.repository, archive);
    const zipped = await call('scan_zip', { zip_path: archive, authorized: true }); assert.equal(zipped.total_dependencies, 4);
    await updateVersion(env.repository, 'traceguard-test-direct', '1.0.1');
    const verified = await call('verify_fixes', { previous_scan_id: scan.scan_id, authorized: true }); assert.equal(verified.resolved_findings.length, 1); assert.equal(verified.remaining_findings.length, 1);
    const missing = await client.callTool({ name: 'get_finding_details', arguments: { scan_id: scan.scan_id, finding_id: 'missing' } }); assert.equal(missing.isError, true);
  } finally { await client.close(); await server.close(); await env.cleanup(); }
});
test('response pagination binds cursors to query/session and respects byte limits', async () => {
  const env = await setup(undefined, { maxOutputBytes: 2048 });
  try {
    const output = new Output(env.scanner); const rows = Array.from({ length: 100 }, (_, id) => ({ id, evidence: 'x'.repeat(300) }));
    const first = output.page(rows, 'test-scope', { page_size: 100 }); assert.ok(first.returned_items < 100); assert.ok(first.next_cursor);
    const second = output.page(rows, 'test-scope', { cursor: first.next_cursor, page_size: 100 }); assert.equal(second.items[0].id, first.returned_items);
    assert.throws(() => output.offset(first.next_cursor, 'wrong-scope'), /invalid|another/i);
    assert.throws(() => new Output(env.scanner).offset(first.next_cursor, 'test-scope'), /invalid|another/i);
    const response = await output.result(first); const bytes = Buffer.byteLength(JSON.stringify(response)); assert.ok(bytes <= 2048);
    assert.equal((response.structuredContent!.metrics as any).response_bytes, bytes);
    const oversized = await output.result({ scan_id: 'test', huge: 'x'.repeat(10000), truncated: false });
    assert.equal(oversized.structuredContent!.truncated, true); assert.ok(oversized.structuredContent!.artifact_path); assert.ok(Buffer.byteLength(JSON.stringify(oversized)) <= 2048);
    assert.equal(JSON.parse(await readFile(String(oversized.structuredContent!.artifact_path), 'utf8')).huge.length, 10000);
  } finally { await env.cleanup(); }
});
test('compiled STDIO server handshake, discovery, errors, stdout hygiene and graceful close', async () => {
  const env = await setup();
  const transport = new StdioClientTransport({ command: process.execPath, args: [path.join(projectDirectory, 'dist/server/index.js')],
    env: { ...process.env as Record<string, string>, TRACEGUARD_ALLOWED_ROOTS: JSON.stringify([env.directory]), TRACEGUARD_DATA_DIR: path.join(env.scanner.settings.dataDir, 'stdio-data') }, stderr: 'pipe' });
  const client = new Client({ name: 'traceguard-stdio-test', version: '1.0.0' }); let stderr = '';
  transport.stderr?.on('data', chunk => { stderr += String(chunk); });
  try {
    await client.connect(transport); assert.ok((await client.listTools()).tools.some(t => t.name === 'generate_security_report'));
    const result = await client.callTool({ name: 'scan_repository', arguments: { repository_path: path.dirname(env.directory), authorized: true } });
    assert.equal(result.isError, true); assert.equal((result.structuredContent!.error as any).code, 'PATH_DENIED');
    assert.equal(stderr, '');
  } finally { await client.close(); await env.cleanup(); }
});
test('configuration generator emits exact absolute paths and valid JSON allowlist', async () => {
  const env = await setup();
  try {
    const { stdout } = await promisify(execFile)(process.execPath, [path.join(projectDirectory, 'scripts/codex-config.mjs'), '--allow', env.repository]);
    const line = (name: string) => stdout.split(/\r?\n/).find(value => value.startsWith(`${name} = `))!.split(' = ').slice(1).join(' = ');
    assert.equal(JSON.parse(line('command')), process.execPath);
    assert.equal(JSON.parse(line('args'))[0], path.join(projectDirectory, 'dist/server/index.js'));
    assert.deepEqual(JSON.parse(JSON.parse(line('TRACEGUARD_ALLOWED_ROOTS'))), [env.repository]);
    assert.ok(path.isAbsolute(JSON.parse(line('TRACEGUARD_DATA_DIR')))); assert.match(stdout, /tool_timeout_sec = 180/);
  } finally { await env.cleanup(); }
});
test('missing authorization configuration fails startup through stderr with empty stdout', async () => {
  await assert.rejects(promisify(execFile)(process.execPath, [path.join(projectDirectory, 'dist/server/index.js')], {
    env: { ...process.env, TRACEGUARD_ALLOWED_ROOTS: '[]' }
  }), (error: any) => error.code === 1 && error.stdout === '' && error.stderr.includes('CONFIG_ERROR') && !error.stderr.includes(' at '));
});
