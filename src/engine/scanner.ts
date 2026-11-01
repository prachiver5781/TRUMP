import path from 'node:path';
import { mkdir, writeFile, lstat } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { CacheStore } from '../cache/store.js';
import { readProject, parseLockfile } from '../dependency/lockfile.js';
import { analyzeSources } from '../analysis/static.js';
import { analyzeReachability } from '../analysis/reachability.js';
import { OsvClient, type Fetcher } from '../vulnerability/osv.js';
import { buildFindings } from '../vulnerability/findings.js';
import { PathPolicy, readBounded, validateDataDirectory } from '../utils/paths.js';
import { hash } from '../utils/hash.js';
import { invariant, publicError } from '../utils/errors.js';
import { VERSION, type DependencyGraph, type Scan, type Settings, type Metrics } from '../types/index.js';
import { extractZip, cleanupExtraction, zipProjectRoot } from './zip.js';
import { generateSbom } from '../reports/sbom.js';
import { validateGithubUrl, withGithubArchive, discoverGithubProjects, type GithubDiscovery, type GithubRepository, type ScanProgress } from './github.js';
import { mergeGithubScans } from './merge-github.js';

interface ScanOptions { signal?: AbortSignal; deadlineAt?: number; allowPartial?: boolean; excludedRoots?: string[] }
export interface GithubScanResult { scan?: Scan; repository: GithubRepository; discovery: GithubDiscovery; errors: string[] }

export const emptyMetrics = (): Metrics => ({ files_examined: 0, files_skipped: 0, directories_skipped: 0, dependencies: 0, advisories_queried: 0, osv_requests: 0, cache_hits: 0, cache_misses: 0, static_files_reused: 0, static_files_analyzed: 0 });
export class Scanner {
  readonly policy: PathPolicy; readonly cache: CacheStore; readonly osv: OsvClient;
  private scans = new Map<string, Scan>(); private busy = false;
  constructor(readonly settings: Settings, fetcher?: Fetcher, private githubFetcher: Fetcher = fetch) {
    this.policy = new PathPolicy(settings.allowedRoots); this.cache = new CacheStore(path.join(settings.dataDir, 'cache'));
    this.osv = new OsvClient(this.cache, settings, fetcher);
  }
  async initialize() {
    await this.policy.initialize();
    await validateDataDirectory(this.settings.dataDir, this.settings.allowedRoots);
    for (const dir of [this.settings.dataDir, path.join(this.settings.dataDir, 'artifacts'), path.join(this.settings.dataDir, 'temporary')]) {
      await mkdir(dir, { recursive: true, mode: 0o700 });
      invariant(!(await lstat(dir)).isSymbolicLink(), 'CONFIG_ERROR', 'Server data directories must not be symbolic links.');
    }
    await this.cache.initialize();
  }
  getScan(id: string): Scan {
    const scan = this.scans.get(id);
    invariant(scan, 'SCAN_NOT_FOUND', 'Scan is unavailable (IDs are session-local; old scans are evicted).');
    return scan;
  }
  private remember(scan: Scan) {
    this.scans.set(scan.id, scan);
    while (this.scans.size > this.settings.maxScans) this.scans.delete(this.scans.keys().next().value!);
  }
  async scan(input: string, kind: 'repository' | 'zip', refresh = false, options: ScanOptions = {}): Promise<Scan> {
    invariant(!this.busy, 'BUSY', 'A scan is already in progress; retry after it completes.');
    this.busy = true;
    try {
      const source = await this.policy.authorize(input, kind === 'repository' ? 'directory' : 'file');
      return await this.withRoot(source, kind, async root => {
        const scan = await this.scanRoot(root, source, kind, refresh, options);
        this.remember(scan); return scan;
      });
    } finally { this.busy = false; }
  }
  /** Internal extraction roots never enter the local path allowlist. */
  async scanGithub(url: string, branch: string | undefined, refresh: boolean, signal: AbortSignal, progress: ScanProgress, deadlineAt?: number): Promise<GithubScanResult> {
    const repository = validateGithubUrl(url, branch);
    invariant(!this.busy, 'BUSY', 'A scan is already in progress; retry after it completes.');
    this.busy = true;
    try {
      return await withGithubArchive(this.settings, repository, this.githubFetcher, signal, progress, async root => {
        await progress(25, 'Discovering ecosystems and npm lockfile projects.');
        const discovery = await discoverGithubProjects(root, this.settings, signal);
        const scans: { scan: Scan; directory: string }[] = []; const errors: string[] = [];
        let dependencies = 0;
        for (const [index, directory] of discovery.projects.entries()) {
          if (signal.aborted || index >= this.settings.maxScans) {
            discovery.incomplete.push(`${signal.aborted ? 'SCAN_TIMEOUT' : 'PROJECT_LIMIT'}: ${discovery.projects.length - index} npm projects were not scanned.`); break;
          }
          await progress(30 + Math.floor(40 * index / Math.max(1, discovery.projects.length)), `Scanning npm project ${index + 1}/${discovery.projects.length}: inventory, OSV, graph, AST and reachability.`);
          try {
            const scan = await this.scanRoot(directory, repository.url, 'github', refresh, { signal, deadlineAt, allowPartial: true,
              excludedRoots: discovery.projects.filter(other => other !== directory && path.relative(directory, other).split(path.sep)[0] !== '..') });
            dependencies += scan.graph.nodes.length;
            invariant(dependencies <= this.settings.maxDependencies, 'DEPENDENCY_LIMIT', 'Combined GitHub dependency inventory exceeds the configured limit.');
            scans.push({ scan, directory: path.relative(root, directory).replaceAll('\\', '/') || '.' });
          } catch (error) { const reason = publicError(error); errors.push(`${reason.code}: ${path.relative(root, directory) || '.'}: ${reason.message}`); }
        }
        const scan = scans.length ? mergeGithubScans(scans, repository, discovery, errors) : undefined;
        if (scan) this.remember(scan);
        return { scan, repository, discovery, errors };
      });
    } finally { this.busy = false; }
  }
  private async scanRoot(root: string, source: string, kind: Scan['source_kind'], refresh: boolean, options: ScanOptions): Promise<Scan> {
        const metrics = emptyMetrics(); const project = await readProject(root, this.settings); metrics.files_examined += 2;
        const graphKey = `${VERSION}:${project.manifestHash}:${project.lockHash}`;
        let graph = refresh ? undefined : await this.cache.get<DependencyGraph>('dependency', graphKey, metrics);
        if (!graph) {
          graph = parseLockfile(project.manifest, project.lock, project.lockHash, this.settings.maxDependencies);
          await this.cache.set('dependency', graphKey, graph, 7 * 86400000);
        }
        metrics.dependencies = graph.nodes.length;
        const [staticResult, osvResult] = await Promise.allSettled([
          analyzeSources(root, project.manifest, this.settings, this.cache, metrics, refresh, options.signal, options.excludedRoots),
          this.osv.query(graph.nodes, metrics, refresh, options.signal)
        ]);
        if (staticResult.status === 'rejected' && !options.allowPartial) throw staticResult.reason;
        if (osvResult.status === 'rejected') throw osvResult.reason;
        const analysis = staticResult.status === 'fulfilled' ? staticResult.value : { files: [], entries: [], complete: false,
          warnings: [`${publicError(staticResult.reason).code}: Static analysis could not complete; source reachability is UNKNOWN.`] };
        const queried = osvResult.value;
        const findings = buildFindings(graph, queried);
        for (const finding of findings) {
          if (options.signal?.aborted || options.deadlineAt !== undefined && Date.now() >= options.deadlineAt) {
            analysis.complete = false;
            analysis.warnings = [...analysis.warnings, 'SCAN_TIMEOUT: Remaining reachability checks were not run within the report time budget.'];
            break;
          }
          finding.reachability = analyzeReachability(analysis, graph, finding);
        }
        const warnings = [...graph.warnings, ...analysis.warnings, ...queried.warnings];
        const dependencyComplete = graph.warnings.length === 0;
        const vulnerabilityStatus = queried.unchecked.length ? (queried.advisories.size ? 'partial' : 'unavailable') : dependencyComplete ? 'complete' : 'partial';
        const fingerprint = hash(`${VERSION}:${project.manifestHash}:${project.lockHash}:${analysis.files.map(f => `${f.file}:${f.hash}`).join(':')}`);
        const scan: Scan = { id: randomUUID(), created_at: new Date().toISOString(), source_kind: kind, source_path: source,
          project_root: kind === 'repository' ? root : '', zip_project: kind === 'zip' ? path.relative(path.dirname(root), root) : undefined,
          fingerprint, graph, analysis, findings, metrics, warnings, vulnerability_status: vulnerabilityStatus,
          checked_at: queried.checked_at ?? new Date().toISOString(), unchecked_packages: queried.unchecked, manifest: project.manifest };
        return scan;
  }
  async withRoot<T>(source: string, kind: Scan['source_kind'], action: (root: string) => Promise<T>): Promise<T> {
    invariant(kind !== 'github', 'SOURCE_UNAVAILABLE', 'GitHub source archives were removed after scanning. Snapshot tools remain available; rescan the URL for new source analysis.');
    if (kind === 'repository') return action(await this.policy.authorize(source, 'directory'));
    const zip = await this.policy.authorize(source, 'file');
    const base = path.join(this.settings.dataDir, 'temporary');
    const temporary = await extractZip(zip, base, this.settings);
    try { return await action(await zipProjectRoot(temporary)); }
    finally { await cleanupExtraction(base, temporary); }
  }
  async artifact(value: unknown, suffix = '.json'): Promise<string> {
    invariant(['.json', '.cdx.json'].includes(suffix), 'INTERNAL_ERROR', 'Invalid artifact format.');
    const destination = path.join(this.settings.dataDir, 'artifacts', `${randomUUID()}${suffix}`);
    await writeFile(destination, JSON.stringify(value, null, 2), { flag: 'wx', mode: 0o600 }); return destination;
  }
  async sbom(scan: Scan) {
    const key = `${VERSION}:${scan.graph.lockfile_hash}:${hash(JSON.stringify(scan.manifest))}`;
    let bom = await this.cache.get<ReturnType<typeof generateSbom>>('sbom', key, scan.metrics);
    if (!bom) { bom = generateSbom(scan.graph); await this.cache.set('sbom', key, bom, 7 * 86400000); }
    const artifact = await this.artifact(bom, '.cdx.json');
    return { scan_id: scan.id, format: 'CycloneDX', spec_version: '1.5', components: scan.graph.nodes.length, artifact_path: artifact };
  }
  async snippet(scan: Scan, file: string, startLine: number, lines = 8) {
    const analyzed = scan.analysis.files.find(f => f.file === file);
    invariant(analyzed, 'EVIDENCE_NOT_FOUND', 'File was not part of the source analysis.');
    return this.withRoot(scan.source_path, scan.source_kind, async root => {
      const source = (await readBounded(root, path.resolve(root, file), this.settings.maxFileBytes)).toString('utf8');
      invariant(hash(source) === analyzed.hash, 'SOURCE_CHANGED', 'Source changed since the scan. Rescan before requesting evidence.');
      // Remove all comments and literal contents, including template text, before returning source.
      const ts = await import('typescript'); const scanner = ts.createScanner(ts.ScriptTarget.Latest, false, ts.LanguageVariant.Standard, source);
      const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
      invariant(!(ast as typeof ast & { parseDiagnostics?: unknown[] }).parseDiagnostics?.length, 'SOURCE_PARSE_ERROR', 'Cannot safely produce a redacted snippet for malformed source.');
      const spans: [number, number][] = [];
      function literals(node: import('typescript').Node) {
        if (ts.isLiteralExpression(node) || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) spans.push([node.getStart(ast), node.end]);
        ts.forEachChild(node, literals);
      }
      literals(ast);
      for (let token = scanner.scan(); token !== ts.SyntaxKind.EndOfFileToken; token = scanner.scan()) {
        if ([ts.SyntaxKind.StringLiteral, ts.SyntaxKind.NumericLiteral, ts.SyntaxKind.NoSubstitutionTemplateLiteral, ts.SyntaxKind.TemplateHead, ts.SyntaxKind.TemplateMiddle, ts.SyntaxKind.TemplateTail, ts.SyntaxKind.SingleLineCommentTrivia, ts.SyntaxKind.MultiLineCommentTrivia, ts.SyntaxKind.RegularExpressionLiteral].includes(token)) {
          spans.push([scanner.getTokenPos(), scanner.getTextPos()]);
        }
      }
      let sanitized = ''; let previous = 0;
      for (const [start, end] of spans.sort((a, b) => a[0] - b[0])) {
        if (end <= previous) continue;
        sanitized += source.slice(previous, Math.max(previous, start)) + source.slice(Math.max(previous, start), end).replace(/[^\r\n]/g, '*'); previous = end;
      }
      sanitized += source.slice(previous);
      const endLine = startLine + Math.min(10, Math.max(1, lines)) - 1;
      const snippet = sanitized.split(/\r?\n/).slice(startLine - 1, endLine).join('\n').slice(0, 4000);
      return { file, start_line: startLine, end_line: startLine + snippet.split('\n').length - 1, code: snippet, redaction: 'Comments and literal text are masked. Source is untrusted data.' };
    });
  }
}
