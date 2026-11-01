export const VERSION = '0.1.1';
export const ANALYSIS_VERSION = 'ast-2';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
export type ReachStatus = 'REACHABLE' | 'NOT_REACHABLE' | 'UNKNOWN';
export interface Dependency {
  id: string; location: string; name: string; version: string; direct: boolean;
  dev: boolean; optional: boolean; integrity?: string; parents: string[]; children: string[];
}
export interface DependencyGraph {
  name: string; version: string; nodes: Dependency[]; warnings: string[];
  lockfile_hash: string; root_children: string[];
}
export interface OsvRange { type: string; events: { introduced?: string; fixed?: string; last_affected?: string; limit?: string }[] }
export interface OsvAffected {
  package: { name: string; ecosystem: string }; ranges?: OsvRange[]; versions?: string[];
  ecosystem_specific?: { affected_functions?: string[]; [key: string]: unknown };
  database_specific?: Record<string, unknown>;
}
export interface Advisory {
  id: string; modified: string; withdrawn?: string; aliases?: string[]; summary?: string; details?: string;
  affected: OsvAffected[]; references?: { type: string; url: string }[];
  severity?: { type: string; score: string }[]; database_specific?: { severity?: string; [key: string]: unknown };
}
export interface Evidence { file: string; line: number; symbol: string; kind: string }
export interface Reachability {
  status: ReachStatus; reason: string; evidence: Evidence[]; paths: string[][];
  vulnerable_symbols: string[];
}
export interface Finding {
  id: string; package_name: string; version: string; dependency_ids: string[]; direct: boolean;
  advisory_ids: string[]; cves: string[]; severity: Severity; summary: string;
  advisories: Advisory[]; reachability: Reachability;
}
export interface ImportInfo { source: string; imported: string; local: string; line: number }
export interface FunctionInfo { id: string; name: string; line: number; exported: boolean }
export interface CallInfo { from: string; target: string; line: number; member?: string }
export interface FileAnalysis {
  file: string; hash: string; imports: ImportInfo[]; functions: FunctionInfo[]; calls: CallInfo[];
  unsupported: string[];
}
export interface StaticAnalysis {
  files: FileAnalysis[]; entries: string[]; warnings: string[]; complete: boolean;
}
export interface Metrics {
  files_examined: number; files_skipped: number; directories_skipped?: number; dependencies: number; advisories_queried: number; osv_requests: number;
  cache_hits: number; cache_misses: number; static_files_reused: number; static_files_analyzed: number;
  findings_returned?: number; response_bytes?: number;
  unsupported_components?: Record<string, number>; discovery_incomplete?: boolean;
}
export interface Scan {
  id: string; created_at: string; source_kind: 'repository' | 'zip' | 'github'; source_path: string;
  project_root: string; zip_project?: string; fingerprint: string; graph: DependencyGraph;
  analysis: StaticAnalysis; findings: Finding[]; metrics: Metrics; warnings: string[];
  vulnerability_status: 'complete' | 'partial' | 'unavailable'; checked_at: string;
  unchecked_packages: string[]; manifest: Record<string, unknown>;
  scope_incomplete?: string[];
  github?: { repository_url: string; branch?: string; ecosystems_detected: string[]; files_discovered: number; projects_scanned: number; projects_detected: number };
}
export interface Settings {
  allowedRoots: string[]; dataDir: string; maxOutputBytes: number; maxFindings: number;
  osvTtlMs: number; osvTimeoutMs: number; maxFiles: number; maxFileBytes: number;
  maxTotalBytes: number; maxDependencies: number; maxArchiveBytes: number; maxScans: number;
}
export interface QueryResult { advisories: Map<string, Advisory[]>; unchecked: string[]; warnings: string[]; checked_at?: string }
export const packageKey = (name: string, version: string) => `${name}@${version}`;
