import path from 'node:path';
import type { Scanner } from '../engine/scanner.js';
import { emptyMetrics } from '../engine/scanner.js';
import { invariant, publicError } from '../utils/errors.js';
import { sourceFiles } from '../utils/paths.js';
import { remediationBatch } from '../remediation/plan.js';
import { chatReportResult, makeChatReport, topFindings, type ChatReport } from '../reports/chat.js';
import type { Scan } from '../types/index.js';

export interface SecurityReportInput {
  repository_path?: string; scan_id?: string; authorized?: true;
  refresh_advisories?: boolean; include_fixes?: boolean; time_budget_ms?: number;
}
export async function securityReport(scanner: Scanner, input: SecurityReportInput) {
  invariant(Boolean(input.repository_path) !== Boolean(input.scan_id), 'INVALID_INPUT', 'Provide exactly one repository_path or existing scan_id.');
  invariant(!input.repository_path || input.authorized === true, 'AUTHORIZATION_REQUIRED', 'A repository report requires explicit authorized: true.');
  invariant(!input.scan_id || !input.refresh_advisories, 'INVALID_INPUT', 'Refreshing advisories requires an explicitly authorized repository_path; a scan_id reuses its snapshot.');
  const started = Date.now(); const budget = input.time_budget_ms ?? 105000;
  invariant(Number.isInteger(budget) && budget >= 1000 && budget <= 110000, 'INVALID_INPUT', 'time_budget_ms must be between 1000 and 110000.');
  const signal = AbortSignal.timeout(budget); let scan: Scan;
  const coreBudget = Math.max(500, budget - Math.min(25000, budget * 0.25));
  try {
    // Reserve up to 25s for verification of top-five advisory-reported fix candidates.
    scan = input.scan_id ? scanner.getScan(input.scan_id) : await scanner.scan(input.repository_path!, 'repository', input.refresh_advisories ?? false,
      { signal: AbortSignal.any([signal, AbortSignal.timeout(coreBudget)]), deadlineAt: started + coreBudget, allowPartial: true });
  } catch (error) {
    const reason = publicError(error);
    if (!input.repository_path || !['PROJECT_NOT_FOUND', 'UNSUPPORTED_LOCKFILE', 'INVALID_PROJECT_JSON', 'INVALID_LOCKFILE', 'FILE_LIMIT', 'FILE_COUNT_LIMIT'].includes(reason.code)) throw error;
    // Only authorized metadata discovery, without loading unsupported source or inventing dependencies.
    const root = await scanner.policy.authorize(input.repository_path, 'directory'); const metrics = emptyMetrics(); const failures: string[] = [];
    try { await sourceFiles(root, scanner.settings, metrics, signal); } catch (e) { const failure = publicError(e); failures.push(`${failure.code}: ${failure.message}`); }
    const report: ChatReport = { project_name: path.basename(root), top: [], fixes: [], elapsed_ms: Date.now() - started, reused_scan: false, metrics,
      coverage: { ecosystems: [], files_analyzed: 0, files_examined: 0,
        unsupported: Object.entries(metrics.unsupported_components ?? {}).map(([name, count]) => `${name}: ${count} detected files/manifests; scanning unsupported`),
        incomplete: [`${reason.code}: ${reason.message}`, 'No resolved dependency, OSV, AST reachability or patched-version results. Counts and score are UNKNOWN.',
          ...(metrics.discovery_incomplete ? ['File discovery stopped at the time budget.'] : [])], errors: failures, warnings: [] } };
    return chatReportResult(report, scanner.settings.maxOutputBytes);
  }
  return chatReportResult(await snapshotReport(scanner, scan, input, started, signal), scanner.settings.maxOutputBytes);
}
export async function snapshotReport(scanner: Scanner, scan: Scan, input: SecurityReportInput, started: number, signal: AbortSignal): Promise<ChatReport> {
  const metrics = input.scan_id ? emptyMetrics() : { ...scan.metrics };
  const top = topFindings(scan); const kinds = new Map<string, 'runtime' | 'dev' | 'optional'>();
  for (const f of top) { const node = scan.graph.nodes.find(n => f.dependency_ids.includes(n.id) && n.direct); kinds.set(f.id, node?.optional ? 'optional' : node?.dev ? 'dev' : 'runtime'); }
  const includeFixes = input.include_fixes ?? true;
  const fixes = includeFixes ? await remediationBatch(top, scanner.osv, metrics, input.refresh_advisories ?? false, signal, kinds) : [];
  return makeChatReport(scan, fixes, metrics, Date.now() - started, Boolean(input.scan_id), includeFixes);
}
