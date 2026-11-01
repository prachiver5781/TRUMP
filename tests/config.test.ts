import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { mkdtemp, mkdir, writeFile, rm, realpath, symlink } from 'node:fs/promises';
import { loadSettings, loadServerEnvironment, parseAllowedRoots, SERVER_ENV_FILE } from '../src/server/config.js';

async function temporary() {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'traceguard-config-'));
  return { directory, cleanup: () => rm(directory, { recursive: true, force: true }) };
}
test('allowed roots accepts JSON Windows forward slashes, escaped backslashes and UNC subdirectories', () => {
  for (const root of ['C:/Users/Prachi/projects', 'D:\\Projects\\Node App', '\\\\server\\share\\projects']) {
    assert.deepEqual(parseAllowedRoots(JSON.stringify([root]), 'win32'), [root]);
  }
});
test('allowed roots accepts JSON macOS absolute directory syntax', () => {
  const roots = ['/Users/prachi/projects', '/Volumes/Work/Node App'];
  assert.deepEqual(parseAllowedRoots(JSON.stringify(roots), 'darwin'), roots);
});
test('malformed JSON reports a distinct useful error without echoing supplied values', () => {
  for (const raw of ['[C:/Users/Prachi]', "['/Users/prachi']", '["C:\\Users\\Prachi"]', '["/Users/prachi",]', 'PRIVATE_CONFIG_VALUE']) {
    assert.throws(() => parseAllowedRoots(raw), (error: any) => error.code === 'CONFIG_ERROR' && error.message.includes('invalid JSON') && error.message.includes('forward slashes') && !error.message.includes('PRIVATE_CONFIG_VALUE'));
  }
});
test('missing, empty, non-array, non-string, relative and unlimited roots fail closed', () => {
  for (const raw of [undefined, '', '[]', 'null', '{}', '"/Users/prachi"', '[1]', '[null]', '[""]', '["relative"]', '["~/projects"]', JSON.stringify(Array(33).fill('/Users/prachi'))]) {
    assert.throws(() => parseAllowedRoots(raw, 'darwin'), { code: 'CONFIG_ERROR' });
  }
  for (const root of ['C:projects', '\\projects', '/Users/prachi', '*']) assert.throws(() => parseAllowedRoots(JSON.stringify([root]), 'win32'), /absolute/);
  assert.throws(() => parseAllowedRoots(JSON.stringify(['C:/Users/Prachi']), 'darwin'), /absolute/);
});
test('filesystem/drive roots, normalized root escapes and control characters are rejected', () => {
  for (const root of ['C:/', 'C:\\', 'C:/projects/..', '\\\\server\\share', '//server/share/']) assert.throws(() => parseAllowedRoots(JSON.stringify([root]), 'win32'), /specific directory/);
  for (const root of ['/', '/tmp/..']) assert.throws(() => parseAllowedRoots(JSON.stringify([root]), 'darwin'), /specific directory/);
  assert.throws(() => parseAllowedRoots(JSON.stringify(['/Users/\0prachi']), 'darwin'), /control characters/);
});
test('native directories are canonicalized and duplicates removed', async () => {
  const env = await temporary();
  try {
    const roots = [env.directory, env.directory.replaceAll('\\', '/'), path.join(env.directory, '.')];
    const settings = loadSettings({ TRACEGUARD_ALLOWED_ROOTS: JSON.stringify(roots) });
    assert.deepEqual(settings.allowedRoots, [await realpath(env.directory)]);
  } finally { await env.cleanup(); }
});
test('missing directory and regular file receive indexed configuration errors', async () => {
  const env = await temporary();
  try {
    const file = path.join(env.directory, 'file'); await writeFile(file, 'x');
    assert.throws(() => loadSettings({ TRACEGUARD_ALLOWED_ROOTS: JSON.stringify([path.join(env.directory, 'absent')]) }), /\[0\].*existing, accessible directory/);
    assert.throws(() => loadSettings({ TRACEGUARD_ALLOWED_ROOTS: JSON.stringify([file]) }), /\[0\].*directory, not a file/);
  } finally { await env.cleanup(); }
});
test('an authorized directory alias is canonicalized but an alias to a filesystem root is rejected', async () => {
  const env = await temporary();
  try {
    const target = path.join(env.directory, 'target'); await mkdir(target);
    const alias = path.join(env.directory, 'alias'); await symlink(target, alias, process.platform === 'win32' ? 'junction' : 'dir');
    assert.deepEqual(loadSettings({ TRACEGUARD_ALLOWED_ROOTS: JSON.stringify([alias]) }).allowedRoots, [await realpath(target)]);
    const rootAlias = path.join(env.directory, 'root-alias'); await symlink(path.parse(env.directory).root, rootAlias, process.platform === 'win32' ? 'junction' : 'dir');
    assert.throws(() => loadSettings({ TRACEGUARD_ALLOWED_ROOTS: JSON.stringify([rootAlias]) }), /resolves to a filesystem/);
  } finally { await env.cleanup(); }
});
test('server .env loads quoted JSON and numeric values without changing process.env', async () => {
  const env = await temporary();
  try {
    const file = path.join(env.directory, '.env'); const roots = JSON.stringify([env.directory]);
    await writeFile(file, `\uFEFF# server settings\r\nTRACEGUARD_ALLOWED_ROOTS='${roots}'\r\nTRACEGUARD_MAX_FINDINGS=3\r\nNODE_OPTIONS=--inspect\r\nUNRELATED_PRIVATE_VALUE=do-not-load\r\n`);
    const before = process.env.TRACEGUARD_ALLOWED_ROOTS;
    const parsed = loadServerEnvironment({}, file); assert.equal(parsed.TRACEGUARD_ALLOWED_ROOTS, roots);
    assert.equal(loadSettings(parsed).maxFindings, 3); assert.equal(parsed.NODE_OPTIONS, undefined); assert.equal(parsed.UNRELATED_PRIVATE_VALUE, undefined);
    assert.equal(process.env.TRACEGUARD_ALLOWED_ROOTS, before);
  } finally { await env.cleanup(); }
});
test('process/Codex values override .env and invalid explicit roots never fall back', async () => {
  const env = await temporary();
  try {
    const file = path.join(env.directory, '.env'); await writeFile(file, `TRACEGUARD_ALLOWED_ROOTS='${JSON.stringify([env.directory])}'\nTRACEGUARD_MAX_FINDINGS=3\n`);
    const overridden = loadServerEnvironment({ TRACEGUARD_ALLOWED_ROOTS: '[]', TRACEGUARD_MAX_FINDINGS: '7' }, file);
    assert.equal(overridden.TRACEGUARD_ALLOWED_ROOTS, '[]'); assert.equal(overridden.TRACEGUARD_MAX_FINDINGS, '7'); assert.throws(() => loadSettings(overridden), /nonempty JSON/);
    assert.throws(() => loadSettings(loadServerEnvironment({ TRACEGUARD_ALLOWED_ROOTS: '' }, file)), /nonempty JSON/);
  } finally { await env.cleanup(); }
});
test('missing .env is optional but roots are still mandatory', async () => {
  const env = await temporary();
  try {
    assert.deepEqual(loadServerEnvironment({}, path.join(env.directory, 'absent')), {});
    assert.throws(() => loadSettings(loadServerEnvironment({}, path.join(env.directory, 'absent'))), /nonempty JSON/);
  } finally { await env.cleanup(); }
});
test('unsafe .env file types and oversized files are rejected', async () => {
  const env = await temporary();
  try {
    assert.throws(() => loadServerEnvironment({}, env.directory), /regular file/);
    const file = path.join(env.directory, '.env'); await writeFile(file, 'x'.repeat(65537));
    assert.throws(() => loadServerEnvironment({}, file), /64 KiB/);
    const link = path.join(env.directory, 'env-link'); await symlink(env.directory, link, process.platform === 'win32' ? 'junction' : 'dir');
    assert.throws(() => loadServerEnvironment({}, link), /regular file/);
  } finally { await env.cleanup(); }
});
test('dotenv location is tied to the trusted server project rather than cwd', () => {
  assert.equal(path.basename(SERVER_ENV_FILE), '.env');
  assert.equal(SERVER_ENV_FILE, fileURLToPath(new URL('../.env', import.meta.url)));
});
