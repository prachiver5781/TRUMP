import path from 'node:path';
import os from 'node:os';
import { mkdtemp, cp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import yazl from 'yazl';
import { createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Scanner } from '../src/engine/scanner.js';
import { loadSettings } from '../src/server/config.js';
import type { Advisory } from '../src/types/index.js';
import type { Fetcher } from '../src/vulnerability/osv.js';

export const projectDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const directAdvisory: Advisory = {
  id: 'TRACEGUARD-TEST-DIRECT', modified: '2026-01-01T00:00:00Z', aliases: ['TRACEGUARD-TEST-ALIAS'], summary: 'OFFLINE TEST DATA: direct function vulnerability',
  database_specific: { severity: 'CRITICAL' }, affected: [{ package: { name: 'traceguard-test-direct', ecosystem: 'npm' },
    ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }], ecosystem_specific: { affected_functions: ['dangerous'] } }],
  references: [{ type: 'ADVISORY', url: 'https://example.invalid/offline-test-direct' }]
};
export const transitiveAdvisory: Advisory = {
  id: 'TRACEGUARD-TEST-TRANSITIVE', modified: '2026-01-01T00:00:00Z', summary: 'OFFLINE TEST DATA: transitive vulnerability', database_specific: { severity: 'HIGH' },
  affected: [{ package: { name: 'traceguard-test-transitive', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }] }]
};
export function offlineOsv(options: { fail?: boolean; paginate?: boolean; records?: Advisory[]; rateLimit?: boolean } = {}) {
  const calls: { url: string; body?: any }[] = []; const records = options.records ?? [directAdvisory, transitiveAdvisory]; let limited = false;
  const fetcher: Fetcher = async (input, init) => {
    const url = String(input); const body = init?.body ? JSON.parse(String(init.body)) : undefined; calls.push({ url, body });
    if (options.fail) throw new Error('OFFLINE TEST network failure');
    if (options.rateLimit && !limited) { limited = true; return new Response('{}', { status: 429, headers: { 'retry-after': '0' } }); }
    if (url.endsWith('/querybatch')) {
      return Response.json({ results: body.queries.map((q: any) => {
        const found = records.filter(a => a.affected.some(p => p.package.name === q.package.name) && q.version === '1.0.0');
        return options.paginate && !q.page_token && found.length ? { next_page_token: 'test-page-2' } : { vulns: found.map(a => ({ id: a.id, modified: a.modified })) };
      }) });
    }
    const id = decodeURIComponent(url.split('/').at(-1)!); const advisory = records.find(a => a.id === id);
    return advisory ? Response.json(advisory) : new Response('{}', { status: 404 });
  };
  return { fetcher, calls };
}
export async function setup(fetcher: Fetcher = offlineOsv().fetcher, overrides: Record<string, unknown> = {}) {
  const base = await mkdtemp(path.join(os.tmpdir(), 'traceguard-test-'));
  const directory = path.join(base, 'inputs'); await mkdir(directory);
  const repository = path.join(directory, 'repository'); await cp(path.join(projectDirectory, 'fixtures/npm-app'), repository, { recursive: true });
  const settings = { ...loadSettings({ TRACEGUARD_ALLOWED_ROOTS: JSON.stringify([directory]), TRACEGUARD_DATA_DIR: path.join(base, 'data'), TRACEGUARD_OSV_TIMEOUT_MS: '100' }), ...overrides };
  const scanner = new Scanner(settings, fetcher); await scanner.initialize();
  return { directory, repository, scanner, cleanup: () => rm(base, { recursive: true, force: true }) };
}
export async function updateVersion(repository: string, name: string, version: string) {
  const manifest = JSON.parse(await readFile(path.join(repository, 'package.json'), 'utf8'));
  const lock = JSON.parse(await readFile(path.join(repository, 'package-lock.json'), 'utf8'));
  if (manifest.dependencies[name]) manifest.dependencies[name] = version;
  lock.packages[`node_modules/${name}`].version = version;
  await writeFile(path.join(repository, 'package.json'), JSON.stringify(manifest));
  await writeFile(path.join(repository, 'package-lock.json'), JSON.stringify(lock));
}
export async function makeZip(destination: string, entries: { name: string; value: string | Buffer; mode?: number }[]) {
  await mkdir(path.dirname(destination), { recursive: true });
  const zip = new yazl.ZipFile();
  for (const entry of entries) zip.addBuffer(Buffer.from(entry.value), entry.name, { ...(entry.mode ? { mode: entry.mode } : {}) });
  zip.end(); await pipeline(zip.outputStream, createWriteStream(destination));
}
export async function projectZip(repository: string, destination: string) {
  await makeZip(destination, await Promise.all(['package.json', 'package-lock.json', 'src/index.js'].map(async name => ({ name: `project/${name}`, value: await readFile(path.join(repository, name)) }))));
}
