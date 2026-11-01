import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { writeFile } from 'node:fs/promises';
import { setup, projectDirectory } from './helpers.js';
import { Scanner, emptyMetrics } from '../src/engine/scanner.js';
import { remediationFor } from '../src/remediation/plan.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

test('LIVE OSV: real lodash vulnerability, advisory details, fixed-version recheck and STDIO scan', { timeout: 180000 }, async () => {
  const env = await setup(fetch);
  const scanner = new Scanner({ ...env.scanner.settings, osvTimeoutMs: 20000 }, fetch); await scanner.initialize();
  const manifest = { name: 'traceguard-real-osv-test', version: '1.0.0', main: 'index.js', dependencies: { lodash: '4.17.20' } };
  await writeFile(path.join(env.repository, 'package.json'), JSON.stringify(manifest));
  await writeFile(path.join(env.repository, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': manifest, 'node_modules/lodash': { version: '4.17.20' } } }));
  await writeFile(path.join(env.repository, 'index.js'), "const lodash = require('lodash'); lodash.template('hello');");
  try {
    const scan = await scanner.scan(env.repository, 'repository', true);
    assert.equal(scan.vulnerability_status, 'complete', JSON.stringify(scan.warnings)); assert.ok(scan.findings.length > 0);
    assert.ok(scan.findings.some(f => f.cves.length > 0)); assert.ok(scan.findings.every(f => f.advisories.length && f.advisories.every(a => a.references?.length)));
    const fix = await remediationFor(scan.findings[0], scanner.osv, emptyMetrics(), true);
    // Current advisories may also affect a historical fixed version; never assume it is still unaffected.
    assert.ok(fix.advisory_fixed_candidates.length > 0); assert.ok(fix.verification);
    const client = new Client({ name: 'traceguard-live-stdio', version: '1.0.0' });
    const transport = new StdioClientTransport({ command: process.execPath, args: [path.join(projectDirectory, 'dist/server/index.js')],
      env: { ...process.env as Record<string, string>, TRACEGUARD_ALLOWED_ROOTS: JSON.stringify([env.directory]), TRACEGUARD_DATA_DIR: scanner.settings.dataDir }, stderr: 'pipe' });
    try {
      await client.connect(transport); const result = await client.callTool({ name: 'scan_repository', arguments: { repository_path: env.repository, authorized: true } });
      assert.equal(result.isError, undefined); const summary = result.structuredContent as any;
      assert.equal(summary.vulnerability_status, 'complete'); assert.ok(summary.total_findings > 0);
      await writeFile(path.join(projectDirectory, 'docs/live-osv-results.json'), JSON.stringify({ observed_at: new Date().toISOString(), package: 'lodash', version: '4.17.20',
        findings: scan.findings.map(f => ({ advisory_ids: f.advisory_ids, cves: f.cves, severity: f.severity, reachability: f.reachability.status })),
        remediation_example: fix, stdio_summary: summary, serialized_tool_result_bytes: Buffer.byteLength(JSON.stringify(result)) }, null, 2));
      console.error(JSON.stringify({ label: 'LIVE_OSV_STDIO_MEASUREMENT', dependencies: summary.total_dependencies, findings: summary.total_findings, bytes: Buffer.byteLength(JSON.stringify(result)), metrics: summary.metrics }));
    } finally { await client.close(); }
  } finally { await env.cleanup(); }
});
