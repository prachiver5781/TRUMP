import semver from 'semver';
import type { Finding, Metrics, QueryResult, Scan } from '../types/index.js';
import { packageKey } from '../types/index.js';
import { fixedCandidates, advisoryAffects } from '../vulnerability/matching.js';
import { OsvClient } from '../vulnerability/osv.js';

export interface RemediationItem {
  finding_id: string; affected_package: string; installed_version: string; advisory_fixed_candidates: string[];
  verified_unaffected_version?: string; verification: string; checked_at?: string; recommended_command?: string;
  breaking_change_considerations: string; testing_instructions: string[]; remaining_uncertainty: string[];
}
export async function remediationFor(finding: Finding, osv: OsvClient, metrics: Metrics, refresh = false, kind: 'runtime' | 'dev' | 'optional' = 'runtime'): Promise<RemediationItem> {
  return (await remediationBatch([finding], osv, metrics, refresh, undefined, new Map([[finding.id, kind]])))[0];
}
/** One deduplicated batch for the report; never one query per advisory/finding. */
export async function remediationBatch(findings: Finding[], osv: OsvClient, metrics: Metrics, refresh = false, signal?: AbortSignal,
  kinds = new Map<string, 'runtime' | 'dev' | 'optional'>()): Promise<RemediationItem[]> {
  const candidates = findings.flatMap(f => fixedCandidates(f.advisories, f.package_name, f.version).slice(0, 8).map(version => ({ name: f.package_name, version })));
  const result = await osv.query(candidates, metrics, refresh, signal);
  return findings.map(f => remediationResult(f, result, kinds.get(f.id) ?? 'runtime'));
}
function remediationResult(finding: Finding, result: QueryResult, kind: 'runtime' | 'dev' | 'optional'): RemediationItem {
  const candidates = fixedCandidates(finding.advisories, finding.package_name, finding.version);
  const checked = candidates.slice(0, 8);
  const verified = checked.find(v => finding.advisories.every(a => advisoryAffects(a, finding.package_name, v) === false) && !result.unchecked.includes(packageKey(finding.package_name, v)) && result.advisories.get(packageKey(finding.package_name, v))?.length === 0);
  return {
    finding_id: finding.id, affected_package: finding.package_name, installed_version: finding.version,
    advisory_fixed_candidates: candidates,
    ...(verified ? { verified_unaffected_version: verified, checked_at: result.checked_at ?? new Date().toISOString() } : {}),
    verification: verified ? 'Version is an advisory-reported fix and an OSV exact-version query returned no current advisories (within the configured cache freshness window).' : 'No unaffected candidate could be verified. No safe version is asserted.',
    ...(verified && finding.direct ? { recommended_command: `npm install --ignore-scripts --save-exact --save-${kind === 'dev' ? 'dev' : kind === 'optional' ? 'optional' : 'prod'} -- ${finding.package_name}@${verified}` } : {}),
    breaking_change_considerations: verified && semver.major(verified) !== semver.major(finding.version) ? 'Major version changes; review upstream migration notes and API compatibility.' : 'Even a patch/minor or 0.x update can change behavior; review upstream release notes.',
    testing_instructions: ['Review the advisory references and candidate release notes.', 'After explicit approval, update the appropriate manifest section and lockfile; preserve dev/optional dependency classification.', 'Run the project test/build suite in a trusted environment, then call verify_fixes with the previous scan_id.'],
    remaining_uncertainty: [
      'OSV absence does not prove safety; unknown vulnerabilities and registry publication/availability are not verified.',
      ...(finding.direct ? [] : ['Transitive dependency: update the controlling parent package or evaluate an explicit override. No parent upgrade version is inferred.']),
      ...(candidates.length > 8 ? ['Only the first eight advisory-reported candidates were queried.'] : []),
      ...result.warnings
    ]
  };
}
export function compareScans(previous: Scan, current: Scan) {
  const identifiers = (f: Finding) => new Set([...f.cves, ...f.advisory_ids, ...f.advisories.flatMap(a => a.aliases ?? [])]);
  const matches = (a: Finding, b: Finding) => a.package_name === b.package_name && [...identifiers(a)].some(id => identifiers(b).has(id));
  const resolved: string[] = []; const remaining: string[] = []; const unverified: string[] = [];
  for (const finding of previous.findings) {
    if (current.findings.some(f => matches(finding, f))) remaining.push(finding.id);
    else if (current.vulnerability_status !== 'complete' || current.unchecked_packages.some(p => p.startsWith(`${finding.package_name}@`))) unverified.push(finding.id);
    else resolved.push(finding.id);
  }
  return { previous_scan_id: previous.id, scan_id: current.id, resolved_findings: resolved, remaining_findings: remaining,
    newly_detected_findings: current.findings.filter(f => !previous.findings.some(old => matches(old, f))).map(f => f.id), unverified_findings: unverified,
    verification_scope: 'Compares advisory identities across installed versions; resolved means absent from a complete current OSV scan, not proof of application safety.' };
}
