import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, readlink, symlink, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Scanner } from '../src/engine/scanner.js';
import { createServer } from '../src/server/create.js';
import { Output } from '../src/utils/output.js';
import { within } from '../src/utils/paths.js';
import { setup, offlineOsv, projectZip, projectDirectory } from './helpers.js';

// Include ignored files/directories and metadata; exclude access times changed by reads.
async function snapshot(root: string) {
  const entries: Record<string, unknown> = {};
  async function walk(file: string): Promise<void> {
    const stat = await lstat(file, { bigint: true });
    const metadata = { mode: String(stat.mode), size: String(stat.size), modified: String(stat.mtimeNs), changed: String(stat.ctimeNs) };
    entries[path.relative(root, file)] = stat.isSymbolicLink() ? { ...metadata, link: await readlink(file) }
      : stat.isFile() ? { ...metadata, sha256: createHash('sha256').update(await readFile(file)).digest('hex') } : metadata;
    if (stat.isDirectory()) for (const name of (await readdir(file)).sort()) await walk(path.join(file, name));
  }
  await walk(root); return entries;
}

test('initialization, all MCP tools, cold/warm/forced scans and reports leave inputs byte-for-byte unchanged', async () => {
  const env = await setup();
  const dataDir = path.join(env.scanner.settings.dataDir, 'read-only-verification');
  const scanner = new Scanner({ ...env.scanner.settings, dataDir }, offlineOsv().fetcher);
  const client = new Client({ name: 'traceguard-read-only-test', version: '1.0.0' });
  const server = createServer(scanner);
  try {
    // Existing data in an input must be preserved, including stale caches.
    const legacy = path.join(env.repository, '.traceguard/codex-data/cache'); await mkdir(legacy, { recursive: true });
    await writeFile(path.join(legacy, 'preserve.json'), '{"expires":0,"value":"unchanged"}');
    const archive = path.join(env.directory, 'project.zip'); await projectZip(env.repository, archive);
    const before = await snapshot(env.directory);
    await scanner.initialize();
    const [a, b] = InMemoryTransport.createLinkedPair(); await server.connect(b); await client.connect(a);
    const call = async (name: string, args: Record<string, unknown>) => {
      const result = await client.callTool({ name, arguments: args });
      assert.equal(result.isError, undefined, JSON.stringify(result)); return result.structuredContent as any;
    };
    const scan = await call('scan_repository', { repository_path: env.repository, authorized: true, refresh_advisories: true });
    assert.equal(scan.total_findings, 2);
    const findings = await call('check_vulnerabilities', { scan_id: scan.scan_id });
    const finding_id = findings.items[0].finding_id;
    for (const name of ['get_scan_summary', 'get_dependency_graph', 'analyze_reachability', 'generate_remediation_plan', 'generate_security_report']) {
      await call(name, { scan_id: scan.scan_id });
    }
    for (const name of ['get_finding_details', 'get_impact_analysis']) await call(name, { scan_id: scan.scan_id, finding_id });
    for (let index = 0; index < 2; index++) {
      const bom = await call('generate_sbom', { scan_id: scan.scan_id });
      assert.ok(within(path.join(dataDir, 'artifacts'), bom.artifact_path));
      assert.equal(JSON.parse(await readFile(bom.artifact_path, 'utf8')).bomFormat, 'CycloneDX');
    }
    const warm = await call('scan_repository', { repository_path: env.repository, authorized: true });
    await call('generate_security_report', { repository_path: env.repository, authorized: true });
    assert.ok(warm.metrics.cache_hits > 0); assert.equal(warm.metrics.osv_requests, 0);
    await call('verify_fixes', { previous_scan_id: scan.scan_id, repository_path: env.repository, authorized: true });
    await call('scan_zip', { zip_path: archive, authorized: true, refresh_advisories: true });
    const oversized = await new Output(scanner).result({ report: 'report data '.repeat(5000) });
    assert.equal(oversized.structuredContent!.truncated, true);
    const reportPath = String(oversized.structuredContent!.artifact_path);
    assert.ok(within(path.join(dataDir, 'artifacts'), reportPath));
    assert.equal(JSON.parse(await readFile(reportPath, 'utf8')).report.length, 60000);
    assert.ok((await readdir(path.join(dataDir, 'cache'))).length > 0);
    assert.deepEqual(await readdir(path.join(dataDir, 'temporary')), []);
    assert.deepEqual(await snapshot(env.directory), before);
  } finally { await client.close(); await server.close(); await env.cleanup(); }
});

test('overlapping data paths fail before creating or changing any input files', async () => {
  const env = await setup();
  try {
    const before = await snapshot(env.directory);
    for (const dataDir of [env.repository, path.join(env.repository, '.traceguard/codex-data'), env.directory, path.dirname(env.directory)]) {
      const scanner = new Scanner({ ...env.scanner.settings, dataDir }, offlineOsv().fetcher);
      await assert.rejects(scanner.initialize(), { code: 'CONFIG_ERROR' });
      assert.deepEqual(await snapshot(env.directory), before);
    }
    await assert.rejects(lstat(path.join(env.repository, '.traceguard')), { code: 'ENOENT' });
  } finally { await env.cleanup(); }
});

test('junction/symlink storage ancestors and child directories cannot redirect writes into inputs', async () => {
  const env = await setup();
  try {
    const alias = path.join(env.scanner.settings.dataDir, 'input-alias');
    await symlink(env.repository, alias, process.platform === 'win32' ? 'junction' : 'dir');
    const before = await snapshot(env.directory);
    await assert.rejects(new Scanner({ ...env.scanner.settings, dataDir: path.join(alias, 'new-data') }).initialize(), { code: 'CONFIG_ERROR' });
    for (const child of ['artifacts', 'cache', 'temporary']) {
      const dataDir = path.join(env.scanner.settings.dataDir, `redirect-${child}`); await mkdir(dataDir);
      await symlink(env.repository, path.join(dataDir, child), process.platform === 'win32' ? 'junction' : 'dir');
      await assert.rejects(new Scanner({ ...env.scanner.settings, dataDir }).initialize(), { code: 'CONFIG_ERROR' });
      assert.deepEqual((await readdir(dataDir)).sort(), [child]);
    }
    assert.deepEqual(await snapshot(env.directory), before);
  } finally { await env.cleanup(); }
});

test('compiled STDIO server rejects in-repository storage without stdout or filesystem changes', async () => {
  const env = await setup();
  try {
    const before = await snapshot(env.directory);
    await assert.rejects(promisify(execFile)(process.execPath, [path.join(projectDirectory, 'dist/server/index.js')], {
      env: { ...process.env, TRACEGUARD_ALLOWED_ROOTS: JSON.stringify([env.directory]), TRACEGUARD_DATA_DIR: path.join(env.repository, '.traceguard/codex-data') }
    }), (error: any) => error.code === 1 && error.stdout === '' && error.stderr.includes('CONFIG_ERROR'));
    assert.deepEqual(await snapshot(env.directory), before);
  } finally { await env.cleanup(); }
});
