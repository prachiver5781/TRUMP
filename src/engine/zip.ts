import path from 'node:path';
import { mkdir, mkdtemp, rm, lstat, readdir, realpath } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import yauzl from 'yauzl';
import type { Entry, ZipFile } from 'yauzl';
import type { Settings } from '../types/index.js';
import { invariant, TraceguardError } from '../utils/errors.js';
import { within } from '../utils/paths.js';

export function validateZipEntry(name: string) {
  invariant(name.length > 0 && name.length <= 1024 && !name.includes('\\') && !name.includes('\0') && !name.includes(':') && !name.startsWith('/'), 'UNSAFE_ZIP', 'Unsafe ZIP entry path.');
  const parts = name.replace(/\/$/, '').split('/');
  invariant(parts.length <= 64 && parts.every(p => p && p !== '.' && p !== '..' && !/[. ]$/.test(p) && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(p)), 'UNSAFE_ZIP', 'Unsafe or platform-reserved ZIP entry path.');
}
export async function extractZip(archive: string, directory: string, settings: Settings, signal?: AbortSignal): Promise<string> {
  signal?.throwIfAborted();
  invariant((await lstat(archive)).size <= settings.maxArchiveBytes, 'ZIP_LIMIT', 'ZIP exceeds compressed size limit.');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporary = await mkdtemp(path.join(directory, 'extract-'));
  let active: Promise<void> | undefined;
  try {
    const zip = await new Promise<ZipFile>((resolve, reject) => yauzl.open(archive, { lazyEntries: true, strictFileNames: true, validateEntrySizes: true }, (err, value) => err ? reject(err) : resolve(value!)));
    await new Promise<void>((resolve, reject) => {
      let count = 0; let declaredTotal = 0; let actualTotal = 0; let done = false;
      const destinations = new Set<string>();
      const abort = () => fail(new TraceguardError('SCAN_TIMEOUT', 'ZIP extraction stopped at the report time budget.'));
      function fail(error: unknown) { if (!done) { done = true; signal?.removeEventListener('abort', abort); zip.close(); reject(error instanceof TraceguardError ? error : new TraceguardError('INVALID_ZIP', 'ZIP cannot be safely extracted.')); } }
      zip.on('error', fail);
      zip.on('end', () => { if (!done) { done = true; signal?.removeEventListener('abort', abort); resolve(); } });
      zip.on('entry', (entry: Entry) => {
        active = (async () => {
          signal?.throwIfAborted();
          validateZipEntry(entry.fileName);
          invariant(++count <= settings.maxFiles, 'ZIP_LIMIT', 'ZIP exceeds entry-count limit.');
          const mode = (entry.externalFileAttributes >>> 16) & 0xffff;
          const type = mode & 0o170000;
          invariant(type === 0 || type === 0o100000 || type === 0o040000, 'UNSAFE_ZIP', 'ZIP links and special files are forbidden.');
          invariant(!(entry.generalPurposeBitFlag & 1), 'UNSAFE_ZIP', 'Encrypted ZIP entries are unsupported.');
          declaredTotal += entry.uncompressedSize;
          invariant(entry.uncompressedSize <= settings.maxFileBytes && declaredTotal <= settings.maxTotalBytes, 'ZIP_LIMIT', 'ZIP exceeds expanded size limits.');
          const destination = path.resolve(temporary, entry.fileName);
          invariant(within(temporary, destination), 'UNSAFE_ZIP', 'ZIP entry escapes extraction root.');
          const key = destination.toLowerCase().replace(/[\\/]+$/, '');
          invariant(!destinations.has(key), 'UNSAFE_ZIP', 'Duplicate or case-colliding ZIP entry.'); destinations.add(key);
          if (entry.fileName.endsWith('/')) await mkdir(destination, { recursive: true, mode: 0o700 });
          else {
            await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
            const input = await new Promise<NodeJS.ReadableStream>((res, rej) => zip.openReadStream(entry, (err, stream) => err ? rej(err) : res(stream!)));
            let entryBytes = 0;
            const limiter = new Transform({ transform(chunk: Buffer, _encoding, callback) {
              entryBytes += chunk.length; actualTotal += chunk.length;
              if (entryBytes > settings.maxFileBytes || actualTotal > settings.maxTotalBytes) callback(new TraceguardError('ZIP_LIMIT', 'ZIP expanded size limit exceeded.'));
              else callback(null, chunk);
            } });
            await pipeline(input, limiter, createWriteStream(destination, { flags: 'wx', mode: 0o600 }), { signal });
          }
          if (!done) zip.readEntry();
        })().catch(fail);
      });
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) abort(); else zip.readEntry();
    });
    return temporary;
  } catch (error) { await active?.catch(() => {}); await cleanupExtraction(directory, temporary); throw error; }
}
export async function cleanupExtraction(base: string, temporary: string) {
  invariant(within(path.resolve(base), path.resolve(temporary)) && path.resolve(base) !== path.resolve(temporary) && path.basename(temporary).startsWith('extract-'), 'PATH_DENIED', 'Invalid temporary cleanup target.');
  // realpath also detects a replaced extraction-root link before recursive removal.
  const actual = await realpath(temporary).catch(() => undefined);
  invariant(!actual || within(await realpath(base), actual), 'PATH_DENIED', 'Extraction directory moved outside temporary root.');
  await rm(temporary, { recursive: true, force: true });
}
export async function zipProjectRoot(extracted: string): Promise<string> {
  const isProject = async (dir: string) => {
    const entries = await readdir(dir); return entries.includes('package.json') && entries.includes('package-lock.json');
  };
  if (await isProject(extracted)) return extracted;
  const children = (await readdir(extracted, { withFileTypes: true })).filter(e => e.isDirectory() && e.name !== '__MACOSX');
  if (children.length === 1 && await isProject(path.join(extracted, children[0].name))) return path.join(extracted, children[0].name);
  throw new TraceguardError('PROJECT_NOT_FOUND', 'ZIP must contain one npm project at its root or in a single top-level folder.');
}
