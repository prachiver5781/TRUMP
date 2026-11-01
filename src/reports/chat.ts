import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import type { Finding, Metrics, ReachStatus, Scan, Severity } from '../types/index.js';
import type { RemediationItem } from '../remediation/plan.js';

const severities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const states: ReachStatus[] = ['REACHABLE', 'NOT_REACHABLE', 'UNKNOWN'];
const identifiers = (f: Finding) => [...new Set([...f.advisory_ids, ...f.cves, ...f.advisories.flatMap(a => [a.id, ...(a.aliases ?? [])])])];
export interface AdvisoryGroup { findings: Finding[]; ids: string[]; severity: Severity; reachability: ReachStatus }

/** Connected alias components, across ALL package versions/locations (including bridge aliases). */
export function advisoryGroups(findings: Finding[]): AdvisoryGroup[] {
  const parents = findings.map((_, i) => i); const owner = new Map<string, number>();
  const root = (i: number): number => { while (parents[i] !== i) { parents[i] = parents[parents[i]]; i = parents[i]; } return i; };
  findings.forEach((f, i) => { for (const id of identifiers(f)) { const previous = owner.get(id); if (previous !== undefined) parents[root(i)] = root(previous); else owner.set(id, i); } });
  const grouped = new Map<number, Finding[]>();
  findings.forEach((f, i) => { const key = root(i); const group = grouped.get(key) ?? []; group.push(f); grouped.set(key, group); });
  return [...grouped.values()].map(matches => ({ findings: matches, ids: [...new Set(matches.flatMap(identifiers))].sort(),
    severity: severities.find(s => matches.some(f => f.severity === s))!,
    reachability: matches.some(f => f.reachability.status === 'REACHABLE') ? 'REACHABLE' as const
      : matches.some(f => f.reachability.status === 'UNKNOWN') ? 'UNKNOWN' as const : 'NOT_REACHABLE' as const
  })).sort((a, b) => severities.indexOf(a.severity) - severities.indexOf(b.severity)
    || states.indexOf(a.reachability) - states.indexOf(b.reachability) || a.ids[0].localeCompare(b.ids[0]));
}
export function topFindings(scan: Scan): Finding[] {
  return advisoryGroups(scan.findings).slice(0, 5).map(g => [...g.findings].sort((a, b) => severities.indexOf(a.severity) - severities.indexOf(b.severity)
    || states.indexOf(a.reachability.status) - states.indexOf(b.reachability.status) || Number(b.direct) - Number(a.direct) || a.id.localeCompare(b.id))[0]);
}
export function reportStats(scan: Scan) {
  const groups = advisoryGroups(scan.findings);
  const names = new Set(scan.graph.nodes.map(n => n.name)); const direct = new Set(scan.graph.nodes.filter(n => n.direct).map(n => n.name));
  const vulnerable = new Set(scan.findings.map(f => f.package_name));
  const severity = Object.fromEntries(severities.map(s => [s, groups.filter(g => g.severity === s).length])) as Record<Severity, number>;
  const reachability = Object.fromEntries(states.map(s => [s, groups.filter(g => g.reachability === s).length])) as Record<ReachStatus, number>;
  const unsupported = Object.keys(scan.metrics.unsupported_components ?? {});
  const incomplete = scan.vulnerability_status !== 'complete' || !scan.analysis.complete || unsupported.length > 0 || Boolean(scan.metrics.discovery_incomplete) || Boolean(scan.scope_incomplete?.length);
  const base = Math.max(0, ...groups.map(g => ({ CRITICAL: 80, HIGH: 60, MEDIUM: 30, LOW: 10, UNKNOWN: 30 })[g.severity]));
  const score = !groups.length && incomplete ? null : Math.min(100, base + (reachability.REACHABLE ? 10 : 0) + Math.min(10, Math.max(0, vulnerable.size - 1) * 2));
  const level = score === null ? 'UNKNOWN' : score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW';
  return { dependencies: { total: names.size, direct: direct.size, transitive: names.size - direct.size, vulnerable: vulnerable.size,
    installed_components: new Set(scan.graph.nodes.map(n => `${n.name}@${n.version}`)).size, lockfile_locations: scan.graph.nodes.length,
    vulnerable_components: new Set(scan.findings.map(f => `${f.package_name}@${f.version}`)).size },
    unique_advisories: groups.length, osv_advisory_count: new Set(scan.findings.flatMap(f => f.advisory_ids)).size,
    unique_cve_count: new Set(groups.flatMap(g => g.ids).filter(id => /^CVE-\d{4}-\d+$/.test(id))).size,
    severity, reachability, risk: { score, level, provisional: incomplete || severity.UNKNOWN > 0 }, incomplete };
}
type Stats = ReturnType<typeof reportStats>;
export interface ChatReport {
  scan_id?: string; project_name: string; stats?: Stats; top: Finding[]; fixes: RemediationItem[];
  checked_at?: string; elapsed_ms: number; reused_scan: boolean; metrics: Metrics;
  sbom?: { format: string; components: number; artifact_path: string };
  impact?: { analyzed: number; total: number; truncated: boolean };
  coverage: { ecosystems: string[]; files_analyzed: number; files_examined: number; unsupported: string[]; incomplete: string[]; errors: string[]; warnings: string[];
    detected?: string[]; completed?: string[]; files_discovered?: number; repository?: string; branch?: string };
}
export function makeChatReport(scan: Scan, fixes: RemediationItem[], metrics: Metrics, elapsed: number, reused: boolean, includeFixes: boolean): ChatReport {
  return { scan_id: scan.id, project_name: scan.graph.name, stats: reportStats(scan), top: topFindings(scan), fixes,
    checked_at: scan.checked_at, elapsed_ms: elapsed, reused_scan: reused, metrics,
    coverage: { ecosystems: ['npm (package-lock.json)'], files_analyzed: scan.analysis.files.length, files_examined: scan.metrics.files_examined,
      unsupported: [...Object.entries(scan.metrics.unsupported_components ?? {}).map(([name, count]) => `${name}: ${count} detected files/manifests; dependency/source security checks unsupported`),
        'Generic SAST, secrets, IaC, native binaries and runtime exploit testing are not implemented.'],
      incomplete: [...(scan.scope_incomplete ?? []), ...(scan.vulnerability_status !== 'complete' ? [`Dependency/advisory scan ${scan.vulnerability_status}; ${scan.unchecked_packages.length} package versions unchecked.`] : []),
        ...(!scan.analysis.complete ? ['AST call graph is incomplete; UNKNOWN reachability is not safety.'] : []),
        ...(scan.metrics.discovery_incomplete ? ['File discovery stopped at the time budget.'] : []),
        ...(!includeFixes ? ['Patched-version verification was disabled.'] : fixes.filter(f => !f.verified_unaffected_version).map(f => `${f.affected_package}: no patched candidate verified; manual review required.`))],
      errors: [...new Set([...scan.warnings, ...fixes.flatMap(f => f.remaining_uncertainty)].filter(w => /^(?:OSV_|SCAN_TIMEOUT|FILE_|STATIC_ANALYSIS_LIMIT)/.test(w)))], warnings: scan.warnings } };
}
// Escape untrusted repository/advisory labels; never render their HTML, instructions or snippets.
const text = (value: string, max = 220) => value.replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, ' ').slice(0, max)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/[\\`*_[\]{}()|#!]/g, '\\$&');
const label = (s: string) => s === 'UNKNOWN' ? 'Unknown' : s[0] + s.slice(1).toLowerCase();
const bar = (n: number, max: number) => '█'.repeat(n && max ? Math.max(1, Math.round(n / max * 14)) : 0).padEnd(14, '░');
function charts(report: ChatReport): string {
  const s = report.stats;
  if (!s) return 'Charts unavailable: dependency and vulnerability counts are UNKNOWN.';
  const rows = (values: [string, number][]) => { const max = Math.max(...values.map(([, n]) => n), 1); return values.map(([k, n]) => `${k.padEnd(15)} ${bar(n, max)} ${n}`).join('\n'); };
  return ['Dependencies (unique names)', rows([['Total', s.dependencies.total], ['Vulnerable', s.dependencies.vulnerable]]), '', 'Severity (unique issues)', rows(severities.map(k => [label(k), s.severity[k]])), '',
    'Identifiers (different units)', rows([['OSV records', s.osv_advisory_count], ['Unique CVEs', s.unique_cve_count]]), '', 'Reachability (unique issues)',
    rows([['Reachable', s.reachability.REACHABLE], ['Not reachable', s.reachability.NOT_REACHABLE], ['Unknown', s.reachability.UNKNOWN]])].join('\n');
}
const formula = 'Priority score = highest issue weight (Critical 80 / High 60 / Medium 30 / Low 10 / Unknown 30) + 10 if any issue is statically reachable + 2 per additional vulnerable package (max +10), capped at 100. Levels: 80+ Critical, 60+ High, 30+ Medium, otherwise Low. This is a transparent triage index, not exploit probability. Incomplete results are lower bounds; no matches with incomplete checks = UNKNOWN.';
export function renderChatReport(r: ChatReport, detail: 'full' | 'compact' | 'minimal' = 'full'): string {
  const s = r.stats; const minimal = detail === 'minimal'; const compact = detail !== 'full';
  const risk = s?.risk.score === null || !s ? 'UNKNOWN' : `${s.risk.score}/100${s.risk.provisional ? ' (provisional lower bound)' : ''}`;
  const out = ['## 1. SECURITY OVERVIEW', `**${text(r.project_name, 100)} · Risk: ${risk} · ${label(s?.risk.level ?? 'UNKNOWN')}**`];
  if (r.coverage.repository) out.push(`Repository: ${text(r.coverage.repository)} · Branch: ${text(r.coverage.branch ?? 'UNKNOWN')}.`);
  if (s?.incomplete && !minimal) out.push('**Partial results:** counts describe resolved/returned data and are lower bounds; missing checks do not establish safety. The score prioritizes observed dependency findings, not unanalyzed application security.');
  if (minimal) {
    out.push(`Dependencies: ${s?.dependencies.total ?? 'UNKNOWN'}; direct ${s?.dependencies.direct ?? 'UNKNOWN'}; transitive ${s?.dependencies.transitive ?? 'UNKNOWN'}; vulnerable packages ${s?.dependencies.vulnerable ?? 'UNKNOWN'}; unique issues ${s?.unique_advisories ?? 'UNKNOWN'}.`);
  } else {
    out.push(['| Metric | Count |', '| --- | ---: |', ...[['Total dependencies', s?.dependencies.total], ['Direct dependencies', s?.dependencies.direct], ['Transitive dependencies', s?.dependencies.transitive], ['Vulnerable dependencies (unique packages)', s?.dependencies.vulnerable], ['Unique vulnerability advisories', s?.unique_advisories]].map(([k, v]) => `| ${k} | ${v ?? 'UNKNOWN'} |`)].join('\n'),
      'Dependency counts use unique package names; a name appearing as direct and transitive is counted direct once. Versions come from the lockfile; runtime installation is not verified.');
    if (r.coverage.repository) out.push(`Vulnerable resolved package versions: **${s?.dependencies.vulnerable_components ?? 'UNKNOWN'}** · Unique affected packages: **${s?.dependencies.vulnerable ?? 'UNKNOWN'}**.`);
  }
  out.push('## 2. VULNERABILITY COUNTS', ['| Severity | Count |', '| --- | ---: |', ...severities.map(k => `| ${label(k)} | ${s ? s.severity[k] : 'UNKNOWN'} |`)].join('\n'),
    `OSV advisory records: **${s?.osv_advisory_count ?? 'UNKNOWN'}** · Unique CVE IDs: **${s?.unique_cve_count ?? 'UNKNOWN'}**`,
    `Reachable: **${s?.reachability.REACHABLE ?? 'UNKNOWN'}** · Not reachable: **${s?.reachability.NOT_REACHABLE ?? 'UNKNOWN'}** · Unknown: **${s?.reachability.UNKNOWN ?? 'UNKNOWN'}**`);
  if (!minimal) out.push('Severity/reachability count global alias-deduplicated issues. An issue is reachable if any instance is reachable; otherwise unknown if any instance is unknown. OSV records and CVEs are distinct identifier counts, never added together.');
  out.push('## 3. CHARTS IN CHAT', minimal ? 'Charts omitted to respect the configured output byte limit.' : `\`\`\`text\n${charts(r)}\n\`\`\``);
  out.push('## 4. TOP SECURITY FINDINGS');
  if (minimal) out.push('Finding details omitted by output limit; retrieve with check_vulnerabilities / get_finding_details.');
  else if (!r.top.length) out.push(s?.incomplete || !s ? 'No confirmed findings available; incomplete checks prevent a safety conclusion.' : 'No known OSV matches for the resolved versions within cache freshness; this is not a safety guarantee.');
  else for (const [i, f] of r.top.entries()) {
    const fix = r.fixes.find(x => x.finding_id === f.id);
    out.push(`**${i + 1}. ${text(f.package_name)} @ ${text(f.version)} — ${label(f.severity)}**`,
      `- CVE / OSV: ${text([...new Set([...f.cves, ...f.advisory_ids])].slice(0, 5).join(', '), 300)}`,
      `- Why dangerous (advisory summary, untrusted): ${text(f.summary, compact ? 120 : 220)}`,
      `- Reachability: **${f.reachability.status}** — ${text(f.reachability.reason, compact ? 100 : 200)}`,
      `- Evidence: ${f.reachability.evidence.slice(0, compact ? 1 : 2).map(e => text(`${e.file}:${e.line} (${e.symbol})`, 140)).join('; ') || 'No supported source call-path evidence.'}`,
      `- Recommended fix: ${fix?.verified_unaffected_version ? `${text(fix.verified_unaffected_version)} verified against advisory ranges and exact-version OSV query; ${f.direct ? 'review compatibility before updating.' : 'controlling parent/override needs manual review.'}` : 'No patched version verified; manual review required.'}`,
      ...(r.coverage.repository ? [`- Advisory-reported fixed versions: ${fix?.advisory_fixed_candidates.length ? fix.advisory_fixed_candidates.slice(0, 8).map(v => text(v)).join(', ') : 'Not available.'} (candidates; availability/compatibility unverified).`] : []),
      `- Finding ID: ${f.id}`);
  }
  if (!minimal && s && s.unique_advisories > r.top.length) out.push(`Showing ${r.top.length} of ${s.unique_advisories} unique issues, one representative package/version each. Use check_vulnerabilities for all affected instances.`);
  out.push('## 5. HOW TO FIX');
  if (minimal) out.push('Only advisory-backed, OSV-verified versions may be recommended. Manual review when verification is unavailable.');
  else {
    out.push('Commands below are suggestions only. TRACEGUARD never runs them. Review in a separately authorized development checkout; preserve dependency classification.');
    for (const f of r.top) { const fix = r.fixes.find(x => x.finding_id === f.id);
      out.push(fix?.recommended_command ? `**${text(f.package_name)}**\n\n\`\`\`sh\n${fix.recommended_command}\n\`\`\`\n${compact ? 'Review compatibility, then rescan with verify_fixes.' : text(fix.breaking_change_considerations)}`
        : `**${text(f.package_name)}:** ${fix?.verified_unaffected_version ? `Child candidate ${text(fix.verified_unaffected_version)} was verified. Inspect the dependency chain with \`npm explain -- ${f.package_name}\`; choose a compatible parent update or reviewed override. No parent version is inferred.` : 'No verified patched version; inspect the advisory and request generate_remediation_plan. Do not guess an upgrade.'}`);
    }
    if (!r.top.length) out.push('Complete any unsupported/incomplete checks before choosing upgrades.');
    out.push('Verification means an advisory-reported fix excludes the affected range and OSV returned no known matches within cache freshness. Registry availability, compatibility and unknown defects are not verified. Review migration notes, validate changes in a trusted environment, then use verify_fixes.');
  }
  out.push('## 6. SCAN COVERAGE');
  out.push(`Ecosystems scanned: ${r.coverage.ecosystems.map(x => text(x)).join(', ') || 'None'}. Files analyzed: ${r.coverage.files_analyzed}; examined: ${r.coverage.files_examined}.`);
  if (r.coverage.detected) out.push(`Ecosystems detected: ${r.coverage.detected.map(x => text(x)).join(', ') || 'UNKNOWN'}. Archive files discovered: ${r.coverage.files_discovered ?? 'UNKNOWN'}.`);
  if (r.coverage.completed && !minimal) out.push(`**Checks completed / status:** ${r.coverage.completed.slice(0, 12).map(x => text(x)).join('; ') || 'No analysis completed.'}`);
  if (r.impact && !minimal) out.push(`Impact analysis: ${r.impact.analyzed}/${r.impact.total} affected instances; paths ${r.impact.truncated ? 'bounded/incomplete' : 'completed within graph limits'}. Dependency relationships do not prove exploitation.`);
  if (!minimal) {
    const list = (heading: string, items: string[], fallback: string) => out.push(`**${heading}:** ${items.length ? items.slice(0, compact ? 2 : 4).map(x => text(x, compact ? 140 : 240)).join('; ') + (items.length > (compact ? 2 : 4) ? `; ${items.length - (compact ? 2 : 4)} more omitted.` : '') : fallback}`);
    list('Unsupported components', r.coverage.unsupported, 'No additional ecosystems detected; absence is not proof of complete coverage.');
    list('Incomplete checks', r.coverage.incomplete, 'No interruption reported for supported checks.');
    list('Errors / API timeouts', r.coverage.errors, 'None reported.'); list('Static/dependency limitations', r.coverage.warnings, 'No model warnings.');
    out.push(`Elapsed: ${(r.elapsed_ms / 1000).toFixed(1)}s · Snapshot reused: ${r.reused_scan ? 'yes' : 'no'} · OSV HTTP requests this operation: ${r.metrics.osv_requests} · Cache hits: ${r.metrics.cache_hits}. Advisory snapshot: ${text(r.checked_at ?? 'UNKNOWN')}.`,
      'Read-only: no project scripts, dependency installation, source uploads, or repository edits. No HTML dashboard or webpage is generated.');
  } else out.push(`Incomplete/unsupported: ${r.coverage.incomplete.length + r.coverage.unsupported.length}; API errors/timeouts: ${r.coverage.errors.length}. Read-only; no dashboard files.`);
  out.push('## 7. FINAL VERDICT', `**Overall risk: ${label(s?.risk.level ?? 'UNKNOWN')}${s?.risk.provisional ? ' (provisional)' : ''}. Manual security review: ${!s || s.incomplete || s.unique_advisories ? 'REQUIRED' : 'recommended before production; no blocking issue found in supported checks'}.**`,
    '1. Review reachable and highest-severity issues first; UNKNOWN does not mean safe.',
    '2. Apply only verified candidates after compatibility review; investigate transitive parents manually.',
    '3. Complete coverage gaps and verify the resulting lockfile with verify_fixes.');
  if (!minimal) out.push(`Scoring formula: ${formula}`);
  else out.push('Score formula: max severity weight 80/60/30/10/30 + reachable 10 + extra vulnerable packages (2 each, max 10), cap 100. Incomplete/no matches = UNKNOWN.');
  return out.join('\n\n');
}

/** Dedicated bounded text response. Never falls back to an artifact or an external page. */
export function chatReportResult(report: ChatReport, maxBytes: number): CallToolResult {
  let result: CallToolResult = { content: [] };
  for (const detail of ['full', 'compact', 'minimal'] as const) {
    const abbreviated = detail !== 'full' || (report.stats?.unique_advisories ?? 0) > report.top.length || report.coverage.warnings.length > 4
      || report.coverage.incomplete.length > 4 || report.coverage.unsupported.length > 4 || report.coverage.errors.length > 4
      || (report.coverage.completed?.length ?? 0) > 12
      || report.top.some(f => f.summary.length > 220 || f.reachability.reason.length > 200 || f.reachability.evidence.length > 2 || identifiers(f).length > 5);
    const payload = { ...(report.scan_id ? { scan_id: report.scan_id } : {}), report_format: 'markdown', truncated: abbreviated,
      ...(detail === 'minimal' ? {} : { overview: report.stats, coverage_status: report.stats?.incomplete || !report.stats || report.coverage.incomplete.length || report.coverage.errors.length ? 'incomplete' : 'complete', top_finding_ids: report.top.map(f => f.id), ...(report.sbom ? { sbom: report.sbom } : {}) }),
      next_tool: report.scan_id ? 'check_vulnerabilities' : 'generate_security_report', metrics: { ...(detail === 'minimal' ? {} : report.metrics), findings_returned: detail === 'minimal' ? 0 : report.top.length, response_bytes: 0 } };
    result = { content: [{ type: 'text', text: renderChatReport(report, detail) + (abbreviated ? '\n\nDisplay abbreviated by report/output limits. Counts cover all available results; use the existing detail tools for omitted evidence.' : '') }], structuredContent: payload };
    for (let i = 0; i < 4; i++) payload.metrics.response_bytes = Buffer.byteLength(JSON.stringify(result));
    if (payload.metrics.response_bytes <= maxBytes) return result;
  }
  // Minimum configured budget is 2 KiB. Keep all seven headings with explicit omissions.
  const markdown = renderChatReport(report, 'minimal').replace(/\n\n/g, '\n');
  const payload = { ...(report.scan_id ? { scan_id: report.scan_id } : {}), report_format: 'markdown', truncated: true,
    omission_reason: 'Configured byte limit: charts, evidence and formula details omitted; request a larger report budget or existing detail tools.', metrics: { findings_returned: 0, response_bytes: 0 } };
  result = { content: [{ type: 'text', text: markdown }], structuredContent: payload };
  for (let i = 0; i < 4; i++) payload.metrics.response_bytes = Buffer.byteLength(JSON.stringify(result));
  if (payload.metrics.response_bytes > maxBytes) {
    result.content = [{ type: 'text', text: ['## 1. SECURITY OVERVIEW', 'Risk/counts: UNKNOWN in this display; output budget too small.', '## 2. VULNERABILITY COUNTS', 'Omitted; see scan details.', '## 3. CHARTS IN CHAT', 'Omitted by byte limit.', '## 4. TOP SECURITY FINDINGS', 'Use check_vulnerabilities / get_finding_details.', '## 5. HOW TO FIX', 'Verified candidates only; manual review required.', '## 6. SCAN COVERAGE', 'Partial display; see structured truncation notice. No repository code executed or modified.', '## 7. FINAL VERDICT', 'Review severity/reachability, verify upgrades, complete coverage. Manual review required.'].join('\n\n') }];
    for (let i = 0; i < 4; i++) payload.metrics.response_bytes = Buffer.byteLength(JSON.stringify(result));
  }
  return result;
}
