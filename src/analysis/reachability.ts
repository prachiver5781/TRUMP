import type { DependencyGraph, Finding, StaticAnalysis, Evidence } from '../types/index.js';
import { moduleId, resolveLocal } from './static.js';
import { resolveDependency } from '../dependency/lockfile.js';

export function analyzeReachability(analysis: StaticAnalysis, graph: DependencyGraph, finding: Finding): Finding['reachability'] {
  const symbols = [...new Set(finding.advisories.flatMap(a => a.affected.filter(p => p.package.name === finding.package_name && p.package.ecosystem === 'npm')
    .flatMap(p => p.ecosystem_specific?.affected_functions ?? [])).filter(s => typeof s === 'string' && /^[$A-Z_a-z][$\w]*(?:\.[$A-Z_a-z][$\w]*)*$/.test(s)))];
  const unknown = (reason: string, evidence: Evidence[] = []): Finding['reachability'] => ({ status: 'UNKNOWN', reason, evidence, paths: [], vulnerable_symbols: symbols });
  if (!symbols.length) return unknown('Advisories provide no supported affected_functions metadata. Package presence or import alone cannot establish vulnerable-function reachability.');
  const files = new Map(analysis.files.map(f => [f.file, f])); const available = new Set(files.keys());
  const edges = new Map<string, string[]>(); const evidence = new Map<string, Evidence>(); const sinks = new Set<string>();
  const unmodeledPackageCalls = new Set<string>();
  function edge(from: string, to: string, ev?: Evidence) {
    edges.set(from, [...(edges.get(from) ?? []), to]); if (ev) evidence.set(`${from}->${to}`, ev);
  }
  for (const file of analysis.files) {
    for (const imp of file.imports) {
      const local = resolveLocal(imp.source, file.file, available);
      if (local) edge(moduleId(file.file), moduleId(local), { file: file.file, line: imp.line, symbol: imp.source, kind: 'module_import' });
    }
    for (const call of file.calls) {
      if (!call.target.startsWith('import:')) {
        edge(call.from, call.target, { file: file.file, line: call.line, symbol: call.target, kind: 'local_call' }); continue;
      }
      const source = call.target.slice(7); const local = resolveLocal(source, file.file, available);
      if (local) {
        const target = files.get(local)?.functions.find(fn => fn.exported && fn.name === call.member);
        if (target) edge(call.from, target.id, { file: file.file, line: call.line, symbol: call.member!, kind: 'imported_call' });
      } else if (!source.startsWith('.') && !source.startsWith('node:')) {
        const packageName = source.startsWith('@') ? source.split('/').slice(0, 2).join('/') : source.split('/')[0];
        const subpath = source.slice(packageName.length).replace(/^\//, '').replaceAll('/', '.');
        const resolved = resolveDependency(graph, '', packageName);
        const symbol = [subpath, call.member].filter(Boolean).join('.');
        if (resolved && finding.dependency_ids.includes(resolved.id) && symbols.includes(symbol)) {
          const sink = `vulnerable:${finding.id}:${symbol}`; sinks.add(sink);
          edge(call.from, sink, { file: file.file, line: call.line, symbol, kind: 'advisory_symbol_call' });
        } else if (resolved && finding.dependency_ids.includes(resolved.id)) unmodeledPackageCalls.add(call.from);
      }
    }
  }
  const queue = analysis.entries.map(moduleId); const previous = new Map(queue.map(id => [id, undefined as string | undefined]));
  for (let i = 0; i < queue.length && i < 100000; i++) {
    const current = queue[i];
    if (sinks.has(current)) {
      const trace: string[] = []; let at: string | undefined = current;
      while (at) { trace.unshift(at); at = previous.get(at); }
      const proof = trace.slice(1).flatMap((to, index) => evidence.get(`${trace[index]}->${to}`) ?? []);
      return { status: 'REACHABLE', reason: 'An AST call path from a declared/inferred entry reaches a function explicitly identified by advisory metadata. This is static potential reachability, not proof of exploitation or runtime execution.', evidence: proof, paths: [trace], vulnerable_symbols: symbols };
    }
    for (const child of edges.get(current) ?? []) if (!previous.has(child)) { previous.set(child, current); queue.push(child); }
  }
  if (queue.length >= 100000) return unknown('Call-graph traversal exceeded its safety limit.');
  if ([...unmodeledPackageCalls].some(from => previous.has(from))) return unknown('The application calls another export of the vulnerable package. Dependency-internal calls are not modeled, so a path to the affected function cannot be excluded.');
  if (!analysis.complete) return unknown('No supported call path was found, but unsupported constructs, external invocation, or missing entry points prevent a negative conclusion.');
  // Dependency internals are never analyzed, so a transitive path remains unknown.
  if (!finding.direct || graph.nodes.some(n => finding.dependency_ids.includes(n.id) && n.parents.some(p => p !== 'root'))) return unknown('Calls inside dependency packages are not analyzed; transitive reachability is unknown.');
  return { status: 'NOT_REACHABLE', reason: 'No path exists in the supported closed application model. This bounded static result does not establish application safety.', evidence: analysis.entries.map(file => ({ file, line: 1, symbol: '<module>', kind: 'entry_point' })), paths: [], vulnerable_symbols: symbols };
}
