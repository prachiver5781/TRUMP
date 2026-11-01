import path from 'node:path';
import { mkdir, readFile, rename, writeFile, rm, lstat } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { hash } from '../utils/hash.js';
import { VERSION, type Metrics } from '../types/index.js';
import { invariant } from '../utils/errors.js';

export class CacheStore {
  constructor(private directory: string) {}
  async initialize() {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    invariant(!(await lstat(this.directory)).isSymbolicLink(), 'CONFIG_ERROR', 'Cache directory must not be a symbolic link.');
  }
  private location(namespace: string, key: string) { return path.join(this.directory, hash(`${VERSION}:${namespace}:${key}`) + '.json'); }
  async get<T>(namespace: string, key: string, metrics?: Metrics): Promise<T | undefined> {
    try {
      const location = this.location(namespace, key);
      const stat = await lstat(location);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 32 * 1024 * 1024) throw new Error('Invalid cache');
      const entry = JSON.parse(await readFile(location, 'utf8')) as { expires: number; value: T };
      if (!entry || !Number.isFinite(entry.expires) || !Object.hasOwn(entry, 'value')) throw new Error('Invalid cache envelope');
      if (Date.now() >= entry.expires) { await rm(location, { force: true }); throw new Error('Expired'); }
      if (metrics) metrics.cache_hits++;
      return entry.value;
    } catch { if (metrics) metrics.cache_misses++; return undefined; }
  }
  async set(namespace: string, key: string, value: unknown, ttlMs: number) {
    const destination = this.location(namespace, key);
    const temporary = path.join(this.directory, `${randomUUID()}.tmp`);
    try {
      await writeFile(temporary, JSON.stringify({ expires: Date.now() + ttlMs, value }), { flag: 'wx', mode: 0o600 });
      await rename(temporary, destination);
    } finally { await rm(temporary, { force: true }); }
  }
  async invalidate(namespace: string, key: string) { await rm(this.location(namespace, key), { force: true }); }
}
