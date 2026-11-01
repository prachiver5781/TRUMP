import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dataDir = process.env.TRACEGUARD_DATA_DIR ?? path.join(os.tmpdir(), `traceguard-self-scan-${createHash('sha256').update(root).digest('hex').slice(0, 12)}`);
const client = new Client({ name: 'traceguard-self-scan', version: '1.0.0' });
const transport = new StdioClientTransport({ command: process.execPath, args: [path.join(root, 'dist', 'server', 'index.js')],
  env: { ...process.env, TRACEGUARD_ALLOWED_ROOTS: JSON.stringify([root]), TRACEGUARD_DATA_DIR: dataDir }, stderr: 'inherit' });
try {
  await client.connect(transport);
  const result = await client.callTool({ name: 'scan_repository', arguments: { repository_path: root, authorized: true, refresh_advisories: true } }, undefined, { timeout: 180000 });
  if (result.isError) throw new Error(JSON.stringify(result.structuredContent));
  const summary = result.structuredContent;
  let findings; let remediation;
  if (summary.total_findings > 0) {
    findings = (await client.callTool({ name: 'check_vulnerabilities', arguments: { scan_id: summary.scan_id, mode: 'detailed', page_size: 100 } })).structuredContent;
    remediation = (await client.callTool({ name: 'generate_remediation_plan', arguments: { scan_id: summary.scan_id, page_size: 20, refresh_advisories: true } }, undefined, { timeout: 180000 })).structuredContent;
  }
  const reports = path.join(dataDir, 'reports'); await mkdir(reports, { recursive: true });
  const report = { measured_at: new Date().toISOString(), summary, ...(findings ? { findings } : {}), ...(remediation ? { remediation } : {}) };
  await writeFile(path.join(reports, 'self-scan-results.json'), JSON.stringify(report, null, 2));
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  if (summary.vulnerability_status !== 'complete') process.exitCode = 1;
} finally { await client.close(); }
