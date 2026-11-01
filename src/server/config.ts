import path from 'node:path';
import os from 'node:os';
import { constants, lstatSync, openSync, fstatSync, readSync, closeSync, realpathSync, statSync, accessSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';
import type { Settings } from '../types/index.js';
import { invariant, TraceguardError } from '../utils/errors.js';

// Resolve from this trusted installation, never from a scanned repository/Codex cwd.
export const SERVER_ENV_FILE = fileURLToPath(new URL('../../.env', import.meta.url));
const ENV_KEYS = ['TRACEGUARD_ALLOWED_ROOTS', 'TRACEGUARD_DATA_DIR', 'TRACEGUARD_MAX_OUTPUT_BYTES',
  'TRACEGUARD_MAX_FINDINGS', 'TRACEGUARD_OSV_TTL_SECONDS', 'TRACEGUARD_OSV_TIMEOUT_MS'];

export function loadServerEnvironment(base: NodeJS.ProcessEnv = process.env, envFile = SERVER_ENV_FILE): NodeJS.ProcessEnv {
  const result = { ...base }; let descriptor: number | undefined;
  try {
    const entry = lstatSync(envFile);
    invariant(entry.isFile() && !entry.isSymbolicLink(), 'CONFIG_ERROR', 'TRACEGUARD server-local .env must be a regular file, not a symbolic link.');
    descriptor = openSync(envFile, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(descriptor);
    invariant(before.isFile() && before.size <= 65536 && before.dev === entry.dev && before.ino === entry.ino,
      'CONFIG_ERROR', 'TRACEGUARD server-local .env must be a stable regular file no larger than 64 KiB.');
    const buffer = Buffer.alloc(65537); let used = 0;
    while (used < buffer.length) {
      const count = readSync(descriptor, buffer, used, buffer.length - used, used); if (!count) break; used += count;
    }
    const after = fstatSync(descriptor);
    invariant(used <= 65536 && before.size === after.size && before.mtimeMs === after.mtimeMs,
      'CONFIG_ERROR', 'TRACEGUARD server-local .env changed while loading or exceeds 64 KiB.');
    const parsed = parseEnv(buffer.subarray(0, used).toString('utf8').replace(/^\uFEFF/, ''));
    // Only application settings are read; NODE_OPTIONS/PATH and other variables are ignored.
    for (const key of ENV_KEYS) if (result[key] === undefined && parsed[key] !== undefined) result[key] = parsed[key];
    return result;
  } catch (error) {
    if (error instanceof TraceguardError) throw error;
    if (descriptor === undefined && (error as NodeJS.ErrnoException).code === 'ENOENT') return result;
    throw new TraceguardError('CONFIG_ERROR', 'Cannot read TRACEGUARD server-local .env; check its syntax, file type and permissions.');
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}

/** Syntax checks can be tested for both platforms; existence checks use the actual host. */
export function parseAllowedRoots(value: string | undefined, platform: NodeJS.Platform = process.platform): string[] {
  invariant(value !== undefined && value.trim().length > 0, 'CONFIG_ERROR',
    'TRACEGUARD_ALLOWED_ROOTS must be a nonempty JSON array of authorized absolute directories. Set it in the process environment or the server-local .env file.');
  let roots: unknown;
  try { roots = JSON.parse(value); }
  catch {
    throw new TraceguardError('CONFIG_ERROR', 'TRACEGUARD_ALLOWED_ROOTS contains invalid JSON. Use a JSON array of double-quoted paths, e.g. ["C:/Users/Prachi/projects"] on Windows or ["/Users/prachi/projects"] on macOS. Use forward slashes or JSON-escaped backslashes.');
  }
  invariant(Array.isArray(roots) && roots.length > 0 && roots.length <= 32,
    'CONFIG_ERROR', 'TRACEGUARD_ALLOWED_ROOTS must be a nonempty JSON array with 1 to 32 authorized absolute directory paths.');
  const paths = platform === 'win32' ? path.win32 : path.posix;
  return roots.map((root, index) => {
    const label = `TRACEGUARD_ALLOWED_ROOTS[${index}]`;
    invariant(typeof root === 'string' && root.trim().length > 0 && !/[\u0000-\u001f\u007f]/.test(root),
      'CONFIG_ERROR', `${label} must be a nonempty directory path without control characters.`);
    const fullyQualifiedWindows = platform !== 'win32' || /^(?:[A-Za-z]:[\\/]|[\\/]{2}[^\\/]+[\\/][^\\/]+(?:[\\/]|$))/.test(root);
    invariant(paths.isAbsolute(root) && fullyQualifiedWindows, 'CONFIG_ERROR',
      `${label} must be an absolute directory path for this operating system; relative paths and ~ expansion are not allowed.`);
    const normalized = paths.normalize(root);
    invariant(normalized !== paths.parse(normalized).root, 'CONFIG_ERROR', `${label} must name a specific directory, not a filesystem or drive root.`);
    return root;
  });
}

export function loadSettings(env: NodeJS.ProcessEnv = loadServerEnvironment()): Settings {
  const roots = parseAllowedRoots(env.TRACEGUARD_ALLOWED_ROOTS).map((root, index) => {
    try {
      const canonical = realpathSync.native(root);
      invariant(statSync(canonical).isDirectory(), 'CONFIG_ERROR', `TRACEGUARD_ALLOWED_ROOTS[${index}] must be a directory, not a file.`);
      invariant(path.normalize(canonical) !== path.parse(canonical).root, 'CONFIG_ERROR', `TRACEGUARD_ALLOWED_ROOTS[${index}] resolves to a filesystem or drive root; choose a specific directory.`);
      accessSync(canonical, constants.R_OK | constants.X_OK);
      return canonical;
    } catch (error) {
      if (error instanceof TraceguardError) throw error;
      throw new TraceguardError('CONFIG_ERROR', `TRACEGUARD_ALLOWED_ROOTS[${index}] must name an existing, accessible directory. Check the path and permissions.`);
    }
  });
  const integer = (key: string, fallback: number, min: number, max: number) => {
    const n = Number(env[key] ?? fallback);
    invariant(Number.isInteger(n) && n >= min && n <= max, 'CONFIG_ERROR', `Invalid ${key}.`);
    return n;
  };
  const dataDir = env.TRACEGUARD_DATA_DIR ?? path.join(os.tmpdir(), 'traceguard-mcp');
  invariant(path.isAbsolute(dataDir), 'CONFIG_ERROR', 'TRACEGUARD_DATA_DIR must be absolute.');
  return {
    allowedRoots: [...new Map(roots.map(root => [process.platform === 'win32' ? root.toLowerCase() : root, root])).values()], dataDir,
    maxOutputBytes: integer('TRACEGUARD_MAX_OUTPUT_BYTES', 16000, 2048, 100000),
    maxFindings: integer('TRACEGUARD_MAX_FINDINGS', 10, 1, 100),
    osvTtlMs: integer('TRACEGUARD_OSV_TTL_SECONDS', 3600, 0, 86400) * 1000,
    osvTimeoutMs: integer('TRACEGUARD_OSV_TIMEOUT_MS', 15000, 100, 60000),
    maxFiles: 10000, maxFileBytes: 16 * 1024 * 1024, maxTotalBytes: 200 * 1024 * 1024,
    maxDependencies: 20000, maxArchiveBytes: 100 * 1024 * 1024, maxScans: 20
  };
}
