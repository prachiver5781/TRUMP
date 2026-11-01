import type { Finding, Scan } from '../types/index.js';
import type { Output } from '../utils/output.js';

export type Mode = 'summary' | 'standard' | 'detailed';
export function findingView(f: Finding, mode: Mode = 'summary') {
  const compact = { finding_id: f.id, package: f.package_name, version: f.version, severity: f.severity,
    advisory_ids: f.advisory_ids, reachability: f.reachability.status };
  if (mode === 'summary') return compact;
  return { ...compact, cves: f.cves, direct: f.direct, summary: f.summary,
    ...(mode === 'detailed' ? { dependency_ids: f.dependency_ids, reachability_reason: f.reachability.reason, evidence_count: f.reachability.evidence.length } : {}) };
}
export function scanSummary(scan: Scan, output: Output, maxFindings: number, mode: Mode = 'summary') {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  const reachability = { REACHABLE: 0, NOT_REACHABLE: 0, UNKNOWN: 0 };
  for (const f of scan.findings) { counts[f.severity]++; reachability[f.reachability.status]++; }
  const direct = scan.graph.nodes.filter(n => n.direct).length;
  const critical = scan.findings.filter(f => f.severity === 'CRITICAL').slice(0, maxFindings);
  const preview = mode === 'summary' ? critical : scan.findings.slice(0, maxFindings);
  const findingsTruncated = preview.length < scan.findings.length;
  const warnings = mode === 'detailed' ? scan.warnings : scan.warnings.slice(0, mode === 'summary' ? 3 : 10);
  const truncated = findingsTruncated || warnings.length < scan.warnings.length;
  return {
    scan_id: scan.id, project_name: scan.graph.name, total_dependencies: scan.graph.nodes.length,
    direct_dependencies: direct, transitive_dependencies: scan.graph.nodes.length - direct,
    vulnerability_status: scan.vulnerability_status, vulnerability_counts: counts,
    total_findings: scan.findings.length, critical_findings: critical.map(f => findingView(f)),
    ...(mode !== 'summary' ? { findings: preview.map(f => findingView(f, mode)) } : {}),
    reachability_summary: reachability,
    risk_summary: scan.vulnerability_status !== 'complete' ? 'Incomplete vulnerability intelligence or dependency resolution; do not infer safety.' : scan.findings.length ? 'Known vulnerable installed versions detected. Exploitability is assessed separately and may remain unknown.' : 'No known OSV advisories matched the resolved versions within the cache freshness window; this is not a safety guarantee.',
    checked_at: scan.checked_at, warning_count: scan.warnings.length, warnings, warnings_truncated: warnings.length < scan.warnings.length,
    truncated, ...(findingsTruncated ? { next_cursor: output.cursor(`findings:${scan.id}:${mode}`, preview.length), next_tool: 'check_vulnerabilities' } : warnings.length < scan.warnings.length ? { next_tool: 'get_scan_summary', next_mode: 'detailed' } : {}),
    ...(mode === 'detailed' ? { fingerprint: scan.fingerprint, entry_points: scan.analysis.entries, static_analysis_complete: scan.analysis.complete } : {}),
    metrics: { ...scan.metrics }
  };
}
