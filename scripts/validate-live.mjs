// Full real-network validation. Not imported by the production MCP server.
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { readFile, writeFile, mkdir, readdir, access } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { randomUUID, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import yazl from 'yazl';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { AjvJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/ajv-provider.js';
import { parseSource } from '../dist/analysis/static.js';

const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const inputs = JSON.parse(await readFile(path.join(workspace, 'docs/validation-inputs.json'), 'utf8'));
const repository = inputs.repositories[0].directory; const updated = inputs.repositories[1].directory;
const dataDir = path.join(os.tmpdir(), `traceguard-validation-data-${randomUUID()}`);
const report = { started_at: new Date().toISOString(), platform: process.platform, node: process.version, input_preparation: inputs, assertions: [], calls: [], mocked_production_components: [], macos_tested: false, codex_client_tested: false };
const expectedTools = ['scan_repository', 'scan_zip', 'generate_sbom', 'check_vulnerabilities', 'get_dependency_graph', 'analyze_reachability', 'get_impact_analysis', 'generate_remediation_plan', 'verify_fixes', 'get_scan_summary', 'get_finding_details'];
let stderr = ''; let originalScan;
function passed(label) { report.assertions.push(label); console.error(`[validation] PASS ${label}`); }
const transport = new StdioClientTransport({ command: process.execPath, args: [path.join(workspace, 'dist/server/index.js')],
  env: { ...process.env, TRACEGUARD_ALLOWED_ROOTS: JSON.stringify([inputs.root]), TRACEGUARD_DATA_DIR: dataDir, TRACEGUARD_OSV_TIMEOUT_MS: '20000' }, stderr: 'pipe' });
const client = new Client({ name: 'traceguard-full-live-validation', version: '1.0.0' });
transport.stderr?.on('data', chunk => { stderr += String(chunk); });
async function call(name, args, expectError = false) {
  const result = await client.callTool({ name, arguments: args }, undefined, { timeout: 180000 });
  const bytes = Buffer.byteLength(JSON.stringify(result)); assert.ok(bytes <= 16000, `${name} exceeded its byte cap`);
  assert.equal(Boolean(result.isError), expectError, JSON.stringify(result.structuredContent));
  const payload = result.structuredContent; assert.ok(payload);
  assert.equal(payload.metrics.response_bytes, bytes); assert.ok(!JSON.stringify(payload).includes('TRACEGUARD_SOURCE_CANARY_DO_NOT_RETURN'));
  report.calls.push({ tool: name, bytes, is_error: Boolean(result.isError) });
  if (payload.artifact_path && payload.omission_reason) return JSON.parse(await readFile(payload.artifact_path, 'utf8'));
  return payload;
}
async function pages(tool, args, pageSize) {
  const collected = []; let cursor; let pageCount = 0;
  do {
    const result = await call(tool, { ...args, page_size: pageSize, ...(cursor ? { cursor } : {}) });
    assert.ok(Array.isArray(result.items)); assert.ok(result.items.length <= pageSize); collected.push(...result.items);
    cursor = result.next_cursor; assert.ok(++pageCount < 2000); if (!cursor) assert.equal(collected.length, result.total_items);
  } while (cursor);
  return { items: collected, pages: pageCount };
}
async function osvQuery(name, version) {
  const response = await fetch('https://api.osv.dev/v1/query', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ package: { name, ecosystem: 'npm' }, version }), signal: AbortSignal.timeout(30000) });
  assert.ok(response.ok, `OSV oracle HTTP ${response.status}`); const body = await response.json(); assert.ok(!body.next_page_token, 'Oracle query requires extra pages');
  return (body.vulns ?? []).filter(a => !a.withdrawn);
}
async function validateOfficialSbom(bom) {
  const provider = new AjvJsonSchemaValidator(); const loaded = new Map(); const sources = [];
  const base = 'https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/';
  async function load(filename, expectedId) {
    if (loaded.has(filename)) return loaded.get(filename);
    const requested = new URL(filename, base); assert.ok(requested.href.startsWith(base) && requested.pathname.endsWith('.json'));
    let text; let url;
    for (const address of [requested.href, `https://cyclonedx.org/schema/${filename}`]) {
      try {
        const response = await fetch(address, { signal: AbortSignal.timeout(12000) }); assert.ok(response.ok, `${address}: ${response.status}`);
        text = await response.text(); JSON.parse(text); url = address; break;
      } catch (error) { console.error(`[validation] schema download retry: ${address}: ${error.message}`); }
    }
    assert.ok(text && url, `Official schema could not be downloaded: ${filename}`); assert.ok(Buffer.byteLength(text) < 8 * 1024 * 1024);
    const schema = JSON.parse(text); const id = expectedId ?? schema.$id; const normalized = { ...schema, $id: id };
    loaded.set(filename, normalized); const refs = new Set();
    function references(value) { if (!value || typeof value !== 'object') return; if (typeof value.$ref === 'string' && !value.$ref.startsWith('#')) refs.add(value.$ref.split('#')[0]); for (const child of Object.values(value)) references(child); }
    references(schema);
    for (const reference of refs) {
      const name = reference.split('/').at(-1); await load(name, new URL(reference, id).href);
    }
    provider.getValidator(normalized);
    sources.push({ url, sha256: createHash('sha256').update(text).digest('hex') }); return normalized;
  }
  const schema = await load('bom-1.5.schema.json'); const result = provider.getValidator(schema)(bom);
  assert.equal(result.valid, true, result.errorMessage); return { valid: true, schema_sources: sources, format_limitations: ['The SDK AJV provider ignores iri-reference and idn-email; generated SBOMs have no internationalized email/IRI fields.'] };
}
try {
  await client.connect(transport); report.server = client.getServerVersion(); report.server_capabilities = client.getServerCapabilities();
  const tools = await client.listTools(); assert.deepEqual(tools.tools.map(t => t.name).sort(), [...expectedTools].sort()); assert.ok(tools.tools.every(t => t.inputSchema && t.outputSchema));
  report.discovered_tools = tools.tools.map(t => t.name); passed('STDIO initialization and all 11 tool schemas discovered');
  originalScan = await call('scan_repository', { repository_path: repository, authorized: true });
  assert.equal(originalScan.vulnerability_status, 'complete'); assert.equal(originalScan.total_dependencies, inputs.repositories[0].locked_packages); assert.equal(originalScan.direct_dependencies, 3); assert.ok(originalScan.total_findings > 0);
  report.repository_summary = originalScan; passed('real repository scan completed with actual OSV findings');
  const scanId = originalScan.scan_id;
  const findings = await pages('check_vulnerabilities', { scan_id: scanId, mode: 'standard' }, 2);
  assert.equal(new Set(findings.items.map(f => f.finding_id)).size, findings.items.length); assert.equal(findings.items.length, originalScan.total_findings);
  report.findings = findings; passed('findings pagination has no duplicate or missing findings');
  const lodashFindings = findings.items.filter(f => f.package === 'lodash'); assert.ok(lodashFindings.length);
  const oracle = await osvQuery('lodash', '4.17.20'); const oracleIds = new Set(oracle.flatMap(a => [a.id, ...(a.aliases ?? [])]));
  assert.ok(lodashFindings.every(f => [...f.advisory_ids, ...(f.cves ?? [])].every(id => oracleIds.has(id))));
  const safe = await osvQuery('is-number', '7.0.0'); assert.equal(safe.length, 0); assert.ok(!findings.items.some(f => f.package === 'is-number'));
  report.osv_oracle = { lodash_advisory_ids: oracle.map(a => a.id), is_number_7_0_0_advisories: safe.length }; passed('findings and safe dependency cross-checked against direct real OSV responses');
  const graph = await pages('get_dependency_graph', { scan_id: scanId, mode: 'standard' }, 3);
  const nodeIds = new Set(graph.items.map(n => n.id)); assert.equal(nodeIds.size, originalScan.total_dependencies);
  assert.ok(graph.items.every(n => n.parents.every(id => id === 'root' || nodeIds.has(id)) && n.children.every(id => nodeIds.has(id))));
  const express = graph.items.find(n => n.name === 'express'); assert.ok(express.children.some(id => id.endsWith('/body-parser')));
  report.graph = { nodes: graph.items.length, pages: graph.pages, edges: graph.items.reduce((sum, n) => sum + n.children.length, 0), express_children: express.children }; passed('direct/transitive dependency graph and parent/child references validated');
  const transitive = findings.items.find(f => !f.direct); assert.ok(transitive);
  const impact = await pages('get_impact_analysis', { scan_id: scanId, finding_id: transitive.finding_id }, 1);
  assert.ok(impact.items.length && impact.items.every(p => p[0] === 'root')); report.transitive_impact = { finding: transitive, paths: impact.items }; passed('actual transitive vulnerability impact paths verified');
  const reachability = await pages('analyze_reachability', { scan_id: scanId, mode: 'standard' }, 3);
  assert.ok(reachability.items.every(f => ['REACHABLE', 'NOT_REACHABLE', 'UNKNOWN'].includes(f.status) && f.reason));
  report.reachability = { counts: Object.fromEntries(['REACHABLE', 'NOT_REACHABLE', 'UNKNOWN'].map(status => [status, reachability.items.filter(f => f.status === status).length])), real_reachable_function_proven: reachability.items.some(f => f.status === 'REACHABLE') };
  const asts = await Promise.all(['index.js', 'src/render.js'].map(async file => parseSource(file, await readFile(path.join(repository, file), 'utf8'))));
  assert.ok(asts.some(f => f.imports.some(i => i.source === 'lodash'))); assert.ok(asts.some(f => f.functions.some(fn => fn.name === 'render'))); assert.ok(asts.some(f => f.calls.some(c => c.member === 'template')));
  report.static_analysis = asts.map(f => ({ file: f.file, imports: f.imports.length, functions: f.functions.length, calls: f.calls.length, unsupported: f.unsupported })); passed('real AST imports/declarations/calls and conservative reachability outputs verified');
  const details = await call('get_finding_details', { scan_id: scanId, finding_id: lodashFindings[0].finding_id }); assert.ok(details.finding.advisories.some(a => a.references?.length && a.affected.length));
  const paths = await call('analyze_reachability', { scan_id: scanId, finding_id: lodashFindings[0].finding_id, view: 'paths', page_size: 1 });
  assert.ok(Array.isArray(paths.items));
  const sbom = await call('generate_sbom', { scan_id: scanId }); const bom = JSON.parse(await readFile(sbom.artifact_path, 'utf8')); assert.equal(bom.components.length, 52);
  report.sbom = { components: bom.components.length, artifact_path: sbom.artifact_path, ...await validateOfficialSbom(bom) }; passed('CycloneDX SBOM validated against the official 1.5 schema and external schema references');
  await call('generate_sbom', { scan_id: scanId });
  const summary = await call('get_scan_summary', { scan_id: scanId }); assert.equal(summary.total_findings, findings.items.length);
  const warm = await call('scan_repository', { repository_path: repository, authorized: true });
  assert.equal(warm.metrics.osv_requests, 0); assert.equal(warm.metrics.advisories_queried, 0); assert.equal(warm.metrics.static_files_analyzed, 0); assert.equal(warm.metrics.static_files_reused, 2); assert.ok(warm.metrics.cache_hits > 0);
  report.warm_scan = warm; passed('warm scan reuses AST/dependency/advisory caches with exactly zero OSV requests');
  const archive = path.join(inputs.root, 'real-project.zip'); const zip = new yazl.ZipFile();
  for (const file of ['package.json', 'package-lock.json', 'index.js', 'src/render.js']) zip.addFile(path.join(repository, file), `project/${file}`);
  zip.end(); await pipeline(zip.outputStream, createWriteStream(archive));
  const zipped = await call('scan_zip', { zip_path: archive, authorized: true, refresh_advisories: true });
  assert.equal(zipped.vulnerability_status, 'complete'); assert.deepEqual(zipped.vulnerability_counts, originalScan.vulnerability_counts); assert.equal(zipped.total_dependencies, originalScan.total_dependencies); assert.ok(zipped.metrics.osv_requests > 0);
  assert.deepEqual(await readdir(path.join(dataDir, 'temporary')), []); report.zip_summary = zipped; passed('real ZIP scanned with fresh OSV responses; counts match repository and extraction is cleaned');
  const remediation = await call('generate_remediation_plan', { scan_id: scanId, page_size: 2, refresh_advisories: true }); assert.equal(remediation.items.length, 2); assert.ok(remediation.next_cursor);
  const moreRemediation = await call('generate_remediation_plan', { scan_id: scanId, page_size: 2, cursor: remediation.next_cursor }); assert.equal(moreRemediation.items.length, 2);
  report.remediation = { first_page: remediation, second_page_count: moreRemediation.items.length }; passed('real advisory-backed remediation and pagination invoked');
  const verified = await call('verify_fixes', { previous_scan_id: scanId, repository_path: updated, authorized: true }); assert.equal(verified.vulnerability_status, 'complete'); assert.ok(verified.resolved_findings.length > 0); assert.ok(verified.remaining_findings.length > 0);
  report.fix_verification = verified; passed('fresh real dependency-change comparison reports resolved and remaining findings');
  const firstPage = await call('check_vulnerabilities', { scan_id: scanId, page_size: 1 });
  const badCursor = await call('get_dependency_graph', { scan_id: scanId, cursor: firstPage.next_cursor }, true); assert.equal(badCursor.error.code, 'INVALID_CURSOR');
  const denied = await call('scan_repository', { repository_path: path.dirname(inputs.root), authorized: true }, true); assert.equal(denied.error.code, 'PATH_DENIED');
  const after = await readFile(path.join(repository, 'package.json')); assert.equal(JSON.parse(after).dependencies.lodash, '4.17.20');
  await assert.rejects(access(path.join(repository, 'node_modules'))); assert.equal(stderr, ''); passed('path/cursor errors, no target installation/mutation, compact output and clean server stderr verified');
  report.status = 'passed'; report.max_response_bytes = Math.max(...report.calls.map(c => c.bytes)); report.tool_invocations = report.calls.length;
} catch (error) {
  report.status = 'failed'; report.error = error instanceof Error ? error.message : String(error); process.exitCode = 1; console.error(error);
} finally {
  await client.close(); report.completed_at = new Date().toISOString(); report.server_stderr = stderr;
  await mkdir(path.join(workspace, 'docs'), { recursive: true }); await writeFile(path.join(workspace, 'docs/full-validation-results.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ status: report.status, passed_assertions: report.assertions.length, tool_invocations: report.calls.length, findings: originalScan?.total_findings, max_response_bytes: report.max_response_bytes, error: report.error }));
}
