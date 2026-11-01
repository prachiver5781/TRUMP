import path from 'node:path';
import semver from 'semver';
import { readBounded } from '../utils/paths.js';
import { hash } from '../utils/hash.js';
import { invariant, TraceguardError } from '../utils/errors.js';
import type { Dependency, DependencyGraph, Settings } from '../types/index.js';

type RecordValue = Record<string, any>;
const record = (value: unknown): RecordValue => value && typeof value === 'object' && !Array.isArray(value) ? value as RecordValue : {};
const isRecord = (value: unknown): value is RecordValue => Boolean(value && typeof value === 'object' && !Array.isArray(value));
export const validPackageName = (value: string) => /^(?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/i.test(value) && value.length <= 214;
const packageAt = (location: string) => location.slice(location.lastIndexOf('node_modules/') + 13);
const locationIndexes = new WeakMap<DependencyGraph, Map<string, Dependency>>();

export function resolveDependency(graph: DependencyGraph, from: string, name: string): Dependency | undefined {
  let byLocation = locationIndexes.get(graph);
  if (!byLocation) { byLocation = new Map(graph.nodes.map(n => [n.location, n])); locationIndexes.set(graph, byLocation); }
  let current = from;
  while (true) {
    const found = byLocation.get(current ? `${current}/node_modules/${name}` : `node_modules/${name}`);
    if (found) return found;
    if (!current) return undefined;
    const parent = path.posix.dirname(current);
    current = parent === '.' ? '' : parent;
  }
}

export function parseLockfile(manifestInput: unknown, lockInput: unknown, lockfileHash: string, maxDependencies = 20000): DependencyGraph {
  invariant(isRecord(manifestInput) && isRecord(lockInput), 'INVALID_PROJECT_JSON', 'Manifest and lockfile must be JSON objects.');
  const manifest = record(manifestInput); const lock = record(lockInput);
  invariant([1, 2, 3].includes(lock.lockfileVersion), 'UNSUPPORTED_LOCKFILE', 'package-lock.json must use npm lockfileVersion 1, 2, or 3.');
  const name = typeof manifest.name === 'string' ? manifest.name.slice(0, 214) : 'unnamed-project';
  const graph: DependencyGraph = { name, version: typeof manifest.version === 'string' ? manifest.version.slice(0, 100) : '0.0.0', nodes: [], warnings: [], lockfile_hash: lockfileHash, root_children: [] };
  const packages = new Map<string, RecordValue>();
  if (lock.lockfileVersion >= 2) {
    invariant(isRecord(lock.packages), 'INVALID_LOCKFILE', 'Lockfile packages table must be an object.');
    for (const [location, info] of Object.entries(record(lock.packages))) { if (location) packages.set(location, record(info)); }
  } else {
    function flatten(deps: RecordValue, prefix: string, depth = 0) {
      invariant(depth < 128, 'DEPENDENCY_LIMIT', 'Dependency nesting exceeds limit.');
      for (const [depName, info] of Object.entries(deps)) {
        invariant(validPackageName(depName), 'INVALID_LOCKFILE', 'Invalid dependency name.');
        const location = `${prefix ? `${prefix}/` : ''}node_modules/${depName}`;
        const metadata = record(info);
        packages.set(location, { ...metadata, dependencies: record(metadata.requires) });
        invariant(packages.size <= maxDependencies, 'DEPENDENCY_LIMIT', 'Too many lockfile entries.');
        flatten(record(metadata.dependencies), location, depth + 1);
      }
    }
    flatten(record(lock.dependencies), '');
  }
  invariant(packages.size <= maxDependencies, 'DEPENDENCY_LIMIT', 'Too many lockfile entries.');
  for (const [location, info] of packages) {
    invariant(location.length <= 4096 && location.split('/').length <= 256 && !location.includes('\\') && !location.split('/').some(p => p === '..' || p === '.') && !location.includes(':') && !location.startsWith('/'), 'INVALID_LOCKFILE', 'Unsafe package location in lockfile.');
    if (info.link || !location.startsWith('node_modules/')) { graph.warnings.push(`Unsupported workspace or local link: ${location.slice(0, 200)}`); continue; }
    const installedName = packageAt(location);
    const actualName = typeof info.name === 'string' ? info.name : installedName;
    invariant(validPackageName(installedName) && validPackageName(actualName), 'INVALID_LOCKFILE', 'Invalid resolved package name.');
    if (!semver.valid(info.version)) { graph.warnings.push(`Unresolved/non-semver dependency: ${installedName}`); continue; }
    graph.nodes.push({ id: location, location, name: actualName, version: info.version, direct: false,
      dev: Boolean(info.dev || info.devOptional), optional: Boolean(info.optional), parents: [], children: [],
      ...(typeof info.integrity === 'string' && /^sha(?:256|384|512)-[A-Za-z0-9+/=]+$/.test(info.integrity) ? { integrity: info.integrity } : {}) });
  }
  const direct = { ...record(manifest.dependencies), ...record(manifest.devDependencies), ...record(manifest.optionalDependencies) };
  function addEdge(parent: Dependency | undefined, depName: string, declared: unknown, optional = false) {
    invariant(validPackageName(depName), 'INVALID_LOCKFILE', 'Invalid dependency name.');
    const node = resolveDependency(graph, parent?.location ?? '', depName);
    if (!node) { if (!optional) graph.warnings.push(`Unresolved edge: ${parent?.name ?? 'root'} -> ${depName}`); return; }
    if (parent) { if (!parent.children.includes(node.id)) parent.children.push(node.id); }
    else { node.direct = true; if (!graph.root_children.includes(node.id)) graph.root_children.push(node.id); }
    const parentId = parent?.id ?? 'root';
    if (!node.parents.includes(parentId)) node.parents.push(parentId);
    if (typeof declared === 'string' && semver.validRange(declared) && !semver.satisfies(node.version, declared)) {
      graph.warnings.push(`Lockfile/manifest version mismatch: ${depName}@${node.version}`);
    }
  }
  for (const [depName, declared] of Object.entries(direct)) addEdge(undefined, depName, declared, Object.hasOwn(record(manifest.optionalDependencies), depName));
  for (const node of graph.nodes) {
    const info = packages.get(node.location)!;
    const deps = { ...record(info.dependencies), ...record(info.optionalDependencies), ...record(info.peerDependencies) };
    for (const [depName, declared] of Object.entries(deps)) {
      addEdge(node, depName, declared, Object.hasOwn(record(info.optionalDependencies), depName) || record(record(info.peerDependenciesMeta)[depName]).optional);
    }
  }
  graph.warnings = [...new Set(graph.warnings)];
  return graph;
}

export async function readProject(root: string, settings: Settings) {
  const [manifestBuffer, lockBuffer] = await Promise.all([
    readBounded(root, path.join(root, 'package.json'), settings.maxFileBytes),
    readBounded(root, path.join(root, 'package-lock.json'), settings.maxFileBytes)
  ]).catch(error => {
    if (error instanceof TraceguardError) throw error;
    throw new TraceguardError('PROJECT_NOT_FOUND', 'Project must contain readable package.json and package-lock.json regular files.');
  });
  let manifest: RecordValue; let lock: unknown;
  try { manifest = JSON.parse(manifestBuffer.toString('utf8')); lock = JSON.parse(lockBuffer.toString('utf8')); }
  catch { throw new TraceguardError('INVALID_PROJECT_JSON', 'Project manifest or lockfile contains invalid JSON.'); }
  invariant(isRecord(manifest) && isRecord(lock), 'INVALID_PROJECT_JSON', 'Manifest and lockfile must be JSON objects.');
  const selected: RecordValue = {};
  for (const key of ['name', 'version', 'main', 'module', 'bin', 'exports', 'dependencies', 'devDependencies', 'optionalDependencies']) if (key in manifest) selected[key] = manifest[key];
  return { manifest: selected, lock, lockHash: hash(lockBuffer), manifestHash: hash(manifestBuffer) };
}

export function dependencyPaths(graph: DependencyGraph, target: string, maxPaths = 1000): { paths: string[][]; truncated: boolean } {
  const nodes = new Map(graph.nodes.map(n => [n.id, n]));
  const paths: string[][] = []; let truncated = false; let visited = 0;
  function ascend(id: string, tail: string[]) {
    if (++visited > 20000 || paths.length >= maxPaths || tail.length > 128) { truncated = true; return; }
    if (id === 'root') { paths.push(['root', ...tail]); return; }
    if (tail.includes(id)) return;
    for (const parent of nodes.get(id)?.parents ?? []) ascend(parent, [id, ...tail]);
  }
  ascend(target, []);
  return { paths, truncated };
}

export function reverseDependents(graph: DependencyGraph, target: string): string[] {
  const nodes = new Map(graph.nodes.map(n => [n.id, n])); const seen = new Set<string>([target]); const queue = [target];
  for (let index = 0; index < queue.length; index++) {
    for (const parent of nodes.get(queue[index])?.parents ?? []) if (!seen.has(parent)) { seen.add(parent); queue.push(parent); }
  }
  return queue.slice(1);
}
