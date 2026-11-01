import { randomUUID } from 'node:crypto';
import type { Scan, Metrics } from '../types/index.js';
import { hash } from '../utils/hash.js';
import type { GithubDiscovery, GithubRepository } from './github.js';

/** Preserve per-project reachability evidence and globally deduplicate report counts. */
export function mergeGithubScans(parts: { scan: Scan; directory: string }[], repository: GithubRepository, discovery: GithubDiscovery, errors: string[]): Scan {
  const metrics: Metrics = { files_examined: 0, files_skipped: 0, dependencies: 0, advisories_queried: 0,
    osv_requests: 0, cache_hits: 0, cache_misses: 0, static_files_reused: 0, static_files_analyzed: 0 };
  for (const { scan } of parts) {
    for (const [key, value] of Object.entries(scan.metrics)) if (typeof value === 'number') {
      const numbers = metrics as unknown as Record<string, number>; numbers[key] = (numbers[key] ?? 0) + value;
    }
    if (scan.metrics.discovery_incomplete) metrics.discovery_incomplete = true;
  }
  const nodes: Scan['graph']['nodes'] = []; const findings: Scan['findings'] = []; const files: Scan['analysis']['files'] = []; const entries: string[] = [];
  const rootChildren: string[] = [];
  for (const [index, { scan, directory }] of parts.entries()) {
    const id = (value: string) => value === 'root' ? 'root' : `project-${index}:${value}`;
    const file = (value: string) => directory === '.' ? value : `${directory}/${value}`;
    nodes.push(...scan.graph.nodes.map(n => ({ ...n, id: id(n.id), location: file(n.location), parents: n.parents.map(id), children: n.children.map(id) })));
    rootChildren.push(...scan.graph.root_children.map(id));
    findings.push(...scan.findings.map(f => ({ ...f, id: hash(`${directory}:${f.id}`).slice(0, 24), dependency_ids: f.dependency_ids.map(id),
      reachability: { ...f.reachability, evidence: f.reachability.evidence.map(e => ({ ...e, file: file(e.file) })), paths: f.reachability.paths.map(p => p.map(file)) } })));
    files.push(...scan.analysis.files.map(f => ({ ...f, file: file(f.file) }))); entries.push(...scan.analysis.entries.map(file));
  }
  const scopeIncomplete = [...discovery.incomplete, ...errors, ...discovery.unsupported];
  const partial = scopeIncomplete.length > 0 || parts.some(p => p.scan.vulnerability_status !== 'complete');
  return { id: randomUUID(), created_at: new Date().toISOString(), source_kind: 'github', source_path: repository.url, project_root: '',
    fingerprint: hash(parts.map(p => `${p.directory}:${p.scan.fingerprint}`).join(':')),
    graph: { name: `${repository.owner}/${repository.repository}`, version: 'UNKNOWN', nodes, warnings: parts.flatMap(p => p.scan.graph.warnings),
      lockfile_hash: hash(parts.map(p => `${p.directory}:${p.scan.graph.lockfile_hash}`).join(':')), root_children: rootChildren },
    analysis: { files, entries, complete: scopeIncomplete.length === 0 && parts.every(p => p.scan.analysis.complete), warnings: parts.flatMap(p => p.scan.analysis.warnings) },
    findings, metrics, warnings: [...new Set([...parts.flatMap(p => p.scan.warnings), ...scopeIncomplete])],
    vulnerability_status: partial ? parts.every(p => p.scan.vulnerability_status === 'unavailable') ? 'unavailable' : 'partial' : 'complete',
    checked_at: parts.map(p => p.scan.checked_at).sort()[0], unchecked_packages: [...new Set(parts.flatMap(p => p.scan.unchecked_packages))],
    manifest: { name: `${repository.owner}/${repository.repository}`, version: 'UNKNOWN' }, scope_incomplete: scopeIncomplete,
    github: { repository_url: repository.url, ...(repository.branch === undefined ? {} : { branch: repository.branch }), ecosystems_detected: discovery.ecosystems,
      files_discovered: discovery.files_discovered, projects_scanned: parts.length, projects_detected: discovery.projects.length } };
}
