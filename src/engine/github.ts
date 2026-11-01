import path from 'node:path';
import { createWriteStream } from 'node:fs';
import { mkdtemp, readdir, lstat } from 'node:fs/promises';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { Settings } from '../types/index.js';
import type { Fetcher } from '../vulnerability/osv.js';
import { invariant, TraceguardError } from '../utils/errors.js';
import { detectedComponent, skippedDirectory } from '../utils/paths.js';
import { cleanupExtraction, extractZip } from './zip.js';

export interface GithubRepository { url: string; owner: string; repository: string; branch?: string }
export type ScanProgress = (progress: number, message: string) => Promise<void>;
export interface GithubDiscovery {
  projects: string[]; ecosystems: string[]; unsupported: string[]; incomplete: string[];
  files_discovered: number; directories_skipped: number;
}

export function validateGithubUrl(input: string, branch?: string): GithubRepository {
  // Match the original input: URL normalization must not erase traversal, credentials or ports.
  const match = /^https:\/\/github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)\/([A-Za-z0-9_.-]{1,100})\/?$/.exec(input);
  invariant(match, 'INVALID_GITHUB_URL', 'Use https://github.com/owner/repository with no credentials, port, query, fragment or extra path. Supply branch separately.');
  const repository = match[2].replace(/\.git$/, '');
  invariant(repository.length > 0 && repository !== '.' && repository !== '..' && !repository.endsWith('.'), 'INVALID_GITHUB_URL', 'Invalid GitHub repository name.');
  if (branch !== undefined) {
    invariant(branch.length > 0 && branch.length <= 200 && !/[\s\u0000-\u001f\u007f~^:?*\[\\%#]/.test(branch)
      && !branch.includes('..') && !branch.includes('@{') && branch !== '@'
      && branch.split('/').every(part => part.length > 0 && !part.startsWith('.') && !part.endsWith('.') && !part.endsWith('.lock')),
    'INVALID_GITHUB_BRANCH', 'Branch must be a valid branch name without traversal, URL escapes or Git revision syntax.');
  }
  return { url: `https://github.com/${match[1]}/${repository}`, owner: match[1], repository, ...(branch === undefined ? {} : { branch }) };
}

function validateArchiveRedirect(location: string, repository: GithubRepository): string {
  let target: URL;
  try { target = new URL(location); } catch { throw new TraceguardError('GITHUB_REDIRECT_DENIED', 'GitHub returned an invalid archive redirect.'); }
  const prefix = `/${repository.owner}/${repository.repository}/`.toLowerCase();
  invariant(target.origin === 'https://codeload.github.com' && !target.username && !target.password && !target.search && !target.hash
    && target.pathname.toLowerCase().startsWith(prefix) && /^(?:legacy\.zip|zip)\/.+/.test(target.pathname.slice(prefix.length))
    && !/%(?:00|0a|0d|5c)/i.test(target.pathname), 'GITHUB_REDIRECT_DENIED', 'Archive redirects must stay on GitHub codeload for the requested repository.');
  return target.href;
}

/** Never follows a generic redirect or sends authentication/environment credentials. */
export async function withGithubArchive<T>(settings: Settings, repository: GithubRepository, fetcher: Fetcher,
  signal: AbortSignal, progress: ScanProgress, action: (root: string) => Promise<T>): Promise<T> {
  const base = path.join(settings.dataDir, 'temporary');
  const temporary = await mkdtemp(path.join(base, 'extract-github-'));
  try {
    await progress(5, 'Downloading the public GitHub source archive.');
    const request = async (url: string) => {
      signal.throwIfAborted();
      const response = await fetcher(url, { method: 'GET', redirect: 'manual', signal,
        headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'TRACEGUARD-MCP' } });
      if (signal.aborted) { await response.body?.cancel().catch(() => {}); signal.throwIfAborted(); }
      return response;
    };
    const endpoint = `https://api.github.com/repos/${repository.owner}/${repository.repository}/zipball${repository.branch === undefined ? '' : `/${encodeURIComponent(`refs/heads/${repository.branch}`)}`}`;
    let response = await request(endpoint);
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location'); await response.body?.cancel();
      invariant(location, 'GITHUB_REDIRECT_DENIED', 'GitHub archive redirect has no destination.');
      response = await request(validateArchiveRedirect(location, repository));
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new TraceguardError('GITHUB_DOWNLOAD_FAILED', `GitHub archive returned HTTP ${response.status}; the public repository/branch may be unavailable, empty or rate limited.`);
    }
    invariant(response.body, 'GITHUB_DOWNLOAD_FAILED', 'GitHub returned an empty archive response.');
    const archive = path.join(temporary, 'repository.zip');
    const length = Number(response.headers.get('content-length') ?? 0);
    if (!Number.isFinite(length) || length < 0 || length > settings.maxArchiveBytes) {
      await response.body.cancel(); throw new TraceguardError('ZIP_LIMIT', 'GitHub archive exceeds the compressed size limit.');
    }
    let received = 0;
    const limiter = new Transform({ transform(chunk: Buffer, _encoding, callback) {
      received += chunk.length;
      if (received > settings.maxArchiveBytes) callback(new TraceguardError('ZIP_LIMIT', 'GitHub archive exceeds the compressed size limit.'));
      else callback(null, chunk);
    } });
    await pipeline(Readable.fromWeb(response.body as import('node:stream/web').ReadableStream), limiter,
      createWriteStream(archive, { flags: 'wx', mode: 0o600 }), { signal });
    await progress(15, 'Extracting with path, link, entry-count and expanded-size limits.');
    const extracted = await extractZip(archive, temporary, settings, signal);
    const entries = await readdir(extracted, { withFileTypes: true });
    const root = entries.length === 1 && entries[0].isDirectory() ? path.join(extracted, entries[0].name) : extracted;
    return await action(root);
  } catch (error) {
    if (signal.aborted) throw new TraceguardError('SCAN_TIMEOUT', 'GitHub scan stopped at its time budget or was cancelled; results are incomplete.');
    if (error instanceof TraceguardError) throw error;
    throw new TraceguardError('GITHUB_DOWNLOAD_FAILED', 'GitHub archive download or processing failed.');
  } finally { await cleanupExtraction(base, temporary); }
}

/** Metadata only; does not load manifests, source instructions, scripts or dependency code. */
export async function discoverGithubProjects(root: string, settings: Settings, signal: AbortSignal): Promise<GithubDiscovery> {
  const result: GithubDiscovery = { projects: [], ecosystems: [], unsupported: [], incomplete: [], files_discovered: 0, directories_skipped: 0 };
  const ecosystems = new Set<string>(); const unsupported = new Set<string>(); let visited = 0;
  async function walk(directory: string, depth = 0): Promise<void> {
    signal.throwIfAborted();
    invariant(depth <= 64, 'FILE_COUNT_LIMIT', 'GitHub directory nesting exceeds the safety limit.');
    const entries = await readdir(directory, { withFileTypes: true }); const names = new Set(entries.filter(e => e.isFile()).map(e => e.name));
    if (names.has('package.json')) {
      ecosystems.add('npm');
      if (names.has('package-lock.json')) result.projects.push(directory);
      else result.incomplete.push(`${path.relative(root, directory).replaceAll('\\', '/') || '.'}: package.json has no independent package-lock.json; dependencies require a covering lockfile.`);
    }
    for (const entry of entries) {
      signal.throwIfAborted();
      invariant(++visited <= settings.maxFiles, 'FILE_COUNT_LIMIT', 'GitHub repository exceeds the file-count limit.');
      const full = path.join(directory, entry.name);
      invariant(!entry.isSymbolicLink(), 'UNSAFE_ZIP', 'Extracted links are forbidden.');
      if (entry.isDirectory()) {
        if (skippedDirectory(entry.name)) result.directories_skipped++;
        else await walk(full, depth + 1);
      } else if (entry.isFile()) {
        result.files_discovered++;
        invariant((await lstat(full)).size <= settings.maxFileBytes, 'FILE_LIMIT', 'Extracted file exceeds size limit.');
        const component = detectedComponent(entry.name);
        if (component) { ecosystems.add(component); unsupported.add(`${component}: dependency/source security checks unsupported`); }
        if (/\.[cm]?[jt]sx?$/i.test(entry.name)) ecosystems.add('JavaScript/TypeScript');
        if (entry.name === '.gitmodules') unsupported.add('Git submodules are not included in GitHub archives.');
        if (entry.name === '.gitattributes') unsupported.add('Git LFS content availability is not verified; archive attributes may omit files.');
      }
    }
  }
  try { await walk(root); }
  catch (error) {
    if (!signal.aborted) throw error;
    result.incomplete.push('SCAN_TIMEOUT: Repository discovery stopped at the time budget; undetected projects/ecosystems remain UNKNOWN.');
  }
  result.projects.sort(); result.ecosystems = [...ecosystems].sort(); result.unsupported = [...unsupported].sort();
  return result;
}
