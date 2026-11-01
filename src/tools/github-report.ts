import type { Scanner } from '../engine/scanner.js';
import { emptyMetrics } from '../engine/scanner.js';
import { validateGithubUrl, type ScanProgress } from '../engine/github.js';
import { invariant, publicError } from '../utils/errors.js';
import { chatReportResult, type ChatReport } from '../reports/chat.js';
import { snapshotReport } from './security-report.js';
import { dependencyPaths, reverseDependents } from '../dependency/lockfile.js';

export interface GithubReportInput {
  repository_url: string; authorized?: true; branch?: string; refresh_advisories?: boolean; time_budget_ms?: number;
}

export async function githubSecurityReport(scanner: Scanner, input: GithubReportInput, progress: ScanProgress = async () => {}, cancellation?: AbortSignal) {
  invariant(input.authorized === true, 'AUTHORIZATION_REQUIRED', 'GitHub scanning requires explicit authorized: true for the user-provided URL.');
  const repository = validateGithubUrl(input.repository_url, input.branch);
  const budget = input.time_budget_ms ?? 105000;
  invariant(Number.isInteger(budget) && budget >= 1000 && budget <= 110000, 'INVALID_INPUT', 'time_budget_ms must be between 1000 and 110000.');
  const started = Date.now(); const deadline = started + budget;
  const signal = AbortSignal.any([AbortSignal.timeout(budget), ...(cancellation ? [cancellation] : [])]);
  const coreBudget = Math.max(500, budget - Math.min(25000, budget * 0.2));
  // Client progress is advisory: an absent/disconnected progress consumer cannot bypass cleanup.
  const notify: ScanProgress = async (value, message) => { await progress(value, message).catch(() => {}); };
  let report: ChatReport = { project_name: `${repository.owner}/${repository.repository}`, top: [], fixes: [], elapsed_ms: 0, reused_scan: false, metrics: emptyMetrics(),
    coverage: { ecosystems: [], files_analyzed: 0, files_examined: 0, detected: [], completed: [],
      repository: repository.url, branch: repository.branch ?? 'default branch (GitHub selected)',
      unsupported: ['Only npm package-lock.json dependency scans and JavaScript/TypeScript AST analysis are supported.'],
      incomplete: ['Dependency and advisory counts are UNKNOWN until a supported scan snapshot is available.'], errors: [], warnings: [] } };
  try {
    const result = await scanner.scanGithub(repository.url, repository.branch, input.refresh_advisories ?? false,
      AbortSignal.any([signal, AbortSignal.timeout(coreBudget)]), notify, started + coreBudget);
    const { scan, discovery, errors } = result;
    if (!scan) {
      report.coverage.detected = discovery.ecosystems;
      report.coverage.files_discovered = discovery.files_discovered;
      report.coverage.completed = ['Public GitHub archive download', 'Safe ZIP extraction', 'Bounded ecosystem discovery'];
      report.coverage.unsupported.push(...discovery.unsupported);
      report.coverage.incomplete.push(...discovery.incomplete, ...(discovery.projects.length ? [] : ['No supported npm project with package.json and package-lock.json was found.']));
      report.coverage.errors.push(...errors);
    } else {
      await notify(75, 'Core scan snapshot available; generating SBOM and bounded dependency impact results. Partial core results are retained.');
      report = await snapshotReport(scanner, scan, { refresh_advisories: input.refresh_advisories }, started, signal);
      report.coverage.repository = repository.url; report.coverage.branch = repository.branch ?? 'default branch (GitHub selected)';
      report.coverage.detected = discovery.ecosystems; report.coverage.files_discovered = discovery.files_discovered;
      report.coverage.unsupported.push(...discovery.unsupported);
      report.coverage.errors.push(...errors);
      report.coverage.completed = ['Public GitHub archive download', 'Safe ZIP extraction', 'Bounded ecosystem discovery',
        `npm dependency inventory/graph: ${scan.github!.projects_scanned}/${scan.github!.projects_detected} projects`,
        `OSV: ${scan.vulnerability_status}`, `AST/reachability: ${scan.analysis.complete ? 'complete within supported model' : 'partial; UNKNOWN where evidence is insufficient'}`];
      try {
        if (!signal.aborted && Date.now() < deadline) {
          report.sbom = await scanner.sbom(scan);
          report.coverage.completed.push(`CycloneDX 1.5 SBOM: ${report.sbom.components} components`);
        } else report.coverage.incomplete.push('SCAN_TIMEOUT: SBOM generation was not completed within the time budget.');
      } catch (error) { const reason = publicError(error); report.coverage.errors.push(`${reason.code}: SBOM generation failed.`); }
      let analyzed = 0; let truncated = false;
      for (const finding of scan.findings) {
        if (signal.aborted || Date.now() >= deadline) break;
        for (const id of finding.dependency_ids) {
          if (signal.aborted || Date.now() >= deadline) { truncated = true; break; }
          const paths = dependencyPaths(scan.graph, id); truncated ||= paths.truncated;
          reverseDependents(scan.graph, id);
        }
        analyzed++;
      }
      report.impact = { analyzed, total: scan.findings.length, truncated };
      report.coverage.completed.push(`Dependency impact relationships: ${analyzed}/${scan.findings.length} affected instances`);
      if (analyzed < scan.findings.length || truncated) report.coverage.incomplete.push('Impact path analysis was bounded or timed out; request get_impact_analysis for specific findings.');
      report.coverage.completed.push(`Remediation: ${report.fixes.length} priority findings reviewed; ${report.fixes.filter(f => f.verified_unaffected_version).length} patched candidates OSV-verified`);
      if (scan.findings.length > report.fixes.length) report.coverage.incomplete.push('Patched-version verification covers the top five unique issues, one representative instance each; other instances require generate_remediation_plan.');
      if (report.coverage.errors.length || signal.aborted || Date.now() >= deadline) {
        if (report.stats) { report.stats.incomplete = true; report.stats.risk.provisional = true; }
        if (signal.aborted || Date.now() >= deadline) report.coverage.incomplete.push('SCAN_TIMEOUT: Report time budget reached; available results are partial.');
      }
    }
  } catch (error) {
    const reason = publicError(error);
    if (['BUSY', 'CONFIG_ERROR', 'PATH_DENIED'].includes(reason.code)) throw error;
    report.coverage.errors.push(`${reason.code}: ${reason.message}`);
    report.coverage.incomplete.push('Archive acquisition or analysis did not complete. No safety conclusion can be drawn.');
  }
  report.elapsed_ms = Date.now() - started;
  await notify(100, 'Temporary GitHub files removed. Returning the Markdown security report; coverage identifies partial and unsupported checks.');
  return chatReportResult(report, scanner.settings.maxOutputBytes);
}
