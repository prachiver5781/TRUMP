import path from 'node:path';
import { constants } from 'node:fs';
import { open, realpath, lstat, readdir } from 'node:fs/promises';
import { invariant } from './errors.js';
import type { Settings, Metrics } from '../types/index.js';

export function within(root: string, target: string): boolean {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

/** Preflight every storage location before mkdir can change an authorized input. */
export async function validateDataDirectory(directory: string, allowedRoots: string[]): Promise<void> {
  invariant(path.isAbsolute(directory) && !directory.includes('\0'), 'CONFIG_ERROR', 'TRACEGUARD_DATA_DIR must be absolute.');
  async function canonicalLocation(input: string): Promise<string> {
    let ancestor = path.resolve(input); const missing: string[] = [];
    while (true) {
      try { return path.join(await realpath(ancestor), ...missing); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        const parent = path.dirname(ancestor);
        invariant(parent !== ancestor, 'CONFIG_ERROR', 'Cannot resolve TRACEGUARD_DATA_DIR.');
        missing.unshift(path.basename(ancestor)); ancestor = parent;
      }
    }
  }
  const roots = await Promise.all(allowedRoots.map(root => realpath(root)));
  const data = await canonicalLocation(directory);
  for (const candidate of [directory, ...['artifacts', 'cache', 'temporary'].map(name => path.join(directory, name))]) {
    const resolved = await canonicalLocation(candidate);
    invariant(roots.every(root => !within(root, resolved) && !within(resolved, root)), 'CONFIG_ERROR',
      'TRACEGUARD_DATA_DIR and its storage directories must be outside and disjoint from all authorized scan roots.');
    invariant(within(data, resolved), 'CONFIG_ERROR', 'Server storage directories must remain inside TRACEGUARD_DATA_DIR.');
    const entry = await lstat(candidate).catch(error => {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      return undefined;
    });
    invariant(!entry || (entry.isDirectory() && !entry.isSymbolicLink()), 'CONFIG_ERROR', 'Server data directories must be regular directories, not symbolic links.');
  }
}

export class PathPolicy {
  private roots: string[] = [];
  constructor(private configured: string[]) {}
  async initialize() {
    this.roots = await Promise.all(this.configured.map(async p => {
      const resolved = await realpath(p);
      invariant((await lstat(resolved)).isDirectory(), 'CONFIG_ERROR', 'Authorized roots must be directories.');
      return resolved;
    }));
  }
  async authorize(input: string, kind: 'file' | 'directory'): Promise<string> {
    invariant(path.isAbsolute(input) && !input.includes('\0'), 'PATH_DENIED', 'An absolute authorized path is required.');
    const resolved = await realpath(input).catch(() => undefined);
    invariant(resolved && this.roots.some(root => within(root, resolved)), 'PATH_DENIED', 'Path is unavailable or outside authorized roots.');
    const stat = await lstat(resolved);
    invariant(kind === 'file' ? stat.isFile() : stat.isDirectory(), 'INVALID_PATH', `Expected a ${kind}.`);
    return resolved;
  }
}
export async function readBounded(root: string, file: string, maxBytes: number): Promise<Buffer> {
  invariant(within(root, file), 'PATH_DENIED', 'File escapes the project root.');
  const stat = await lstat(file);
  invariant(stat.isFile() && !stat.isSymbolicLink(), 'PATH_DENIED', 'Only regular project files can be read.');
  invariant(within(root, await realpath(file)), 'PATH_DENIED', 'File resolves outside the project root.');
  const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    invariant(before.isFile() && before.size <= maxBytes, 'FILE_LIMIT', 'Project file exceeds the configured size limit.');
    // Read at most maxBytes + 1 even when a file grows during the read.
    const data = Buffer.alloc(Math.min(before.size + 1, maxBytes + 1));
    let used = 0;
    while (used < data.length) {
      const { bytesRead } = await handle.read(data, used, data.length - used, used);
      if (!bytesRead) break;
      used += bytesRead;
    }
    const after = await handle.stat();
    invariant(used <= maxBytes && before.size === after.size && before.mtimeMs === after.mtimeMs,
      'FILE_CHANGED', 'A project file changed during the scan; retry.');
    return data.subarray(0, used);
  } finally { await handle.close(); }
}
export const skippedDirectory = (name: string) => ['node_modules', '.git', '.hg', '.svn', '.traceguard', 'coverage', 'dist', 'build', '.next', 'vendor'].includes(name);
export const detectedComponent = (name: string) => /\.(?:py|pyi)$|^(?:requirements.*\.txt|pyproject\.toml|Pipfile(?:\.lock)?)$/i.test(name) ? 'Python'
    : /\.go$|^go\.(?:mod|sum)$/i.test(name) ? 'Go' : /\.rs$|^Cargo\.(?:toml|lock)$/i.test(name) ? 'Rust'
    : /\.(?:java|kt|scala)$|^pom\.xml$|\.gradle(?:\.kts)?$/i.test(name) ? 'JVM'
    : /\.(?:cs|csproj|fs|fsproj)$|^packages\.config$/i.test(name) ? '.NET'
    : /\.php$|^composer\.(?:json|lock)$/i.test(name) ? 'PHP' : /\.rb$|^Gemfile(?:\.lock)?$/i.test(name) ? 'Ruby'
    : /\.(?:c|h|cpp|hpp|node|dll|so|exe|wasm)$/i.test(name) ? 'Native/binary'
    : /^(?:yarn\.lock|pnpm-lock\.yaml|bun\.lockb?)$/i.test(name) ? 'Non-npm lockfile' : undefined;
export async function sourceFiles(root: string, settings: Settings, metrics: Metrics, signal?: AbortSignal, excludedRoots: string[] = []): Promise<string[]> {
  const result: string[] = []; let visited = 0; let totalBytes = 0;
  async function walk(dir: string, depth = 0) {
    if (signal?.aborted) { metrics.discovery_incomplete = true; return; }
    invariant(depth <= 64, 'FILE_COUNT_LIMIT', 'Project directory nesting exceeds the safety limit.');
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (signal?.aborted) { metrics.discovery_incomplete = true; return; }
      invariant(++visited <= settings.maxFiles, 'FILE_COUNT_LIMIT', 'Project exceeds the file-count limit. Narrow the scan root.');
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) { metrics.files_skipped++; continue; }
      if (entry.isDirectory()) { if (skippedDirectory(entry.name) || excludedRoots.includes(full)) metrics.directories_skipped = (metrics.directories_skipped ?? 0) + 1; else await walk(full, depth + 1); }
      else if (entry.isFile() && /\.(?:[cm]?[jt]sx?)$/i.test(entry.name) && !/\.d\.[cm]?ts$/i.test(entry.name)) {
        const stat = await lstat(full);
        totalBytes += stat.size;
        invariant(stat.size <= Math.min(settings.maxFileBytes, 2 * 1024 * 1024) && totalBytes <= settings.maxTotalBytes, 'FILE_LIMIT', 'Source files exceed scan size limits.');
        result.push(full);
      } else if (!(dir === root && ['package.json', 'package-lock.json'].includes(entry.name))) {
        metrics.files_skipped++;
        const name = entry.isFile() ? detectedComponent(entry.name) : undefined;
        if (name) { metrics.unsupported_components ??= {}; metrics.unsupported_components[name] = (metrics.unsupported_components[name] ?? 0) + 1; }
      }
    }
  }
  await walk(root);
  return result.sort();
}
