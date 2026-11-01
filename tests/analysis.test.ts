import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { writeFile } from 'node:fs/promises';
import { parseSource } from '../src/analysis/static.js';
import { setup } from './helpers.js';

test('AST detects aliased ESM imports, declarations, calls and source lines', () => {
  const parsed = parseSource('index.js', "import { dangerous as run } from 'pkg';\nfunction start(){ run(); }\nstart();");
  assert.deepEqual(parsed.imports[0], { source: 'pkg', imported: 'dangerous', local: 'run', line: 1 });
  assert.equal(parsed.functions[0].name, 'start');
  assert.ok(parsed.calls.some(c => c.target === 'import:pkg' && c.member === 'dangerous' && c.line === 2));
  assert.ok(parsed.calls.some(c => c.from.endsWith('<module>') && c.target.includes('#start:')));
});
test('AST supports CommonJS destructuring and local parameter shadowing', () => {
  const parsed = parseSource('index.cjs', "const { dangerous: run } = require('pkg');\nfunction shadow(run){ run(); }\nfunction invoke(){ run(); }\ninvoke();");
  assert.equal(parsed.imports[0].imported, 'dangerous');
  assert.equal(parsed.calls.filter(c => c.target === 'import:pkg').length, 1);
  assert.ok(parsed.calls.find(c => c.target === 'import:pkg')!.from.includes('#invoke:'));
});
test('a shadowed require function is not interpreted as a package import', () => {
  const parsed = parseSource('index.js', "function require(){ return {}; } const { dangerous } = require('traceguard-test-direct'); dangerous();");
  assert.equal(parsed.imports.length, 0); assert.ok(!parsed.calls.some(c => c.target === 'import:traceguard-test-direct'));
});
test('AST documents dynamic imports, reflection, callbacks and malformed source', () => {
  const parsed = parseSource('app.ts', 'import(process.env.PLUGIN); eval("x"); setTimeout(() => thing(), 1);');
  assert.ok(parsed.unsupported.some(s => s.includes('Dynamic'))); assert.ok(parsed.unsupported.some(s => s.includes('Reflection'))); assert.ok(parsed.unsupported.some(s => s.includes('callback')));
  assert.ok(parseSource('bad.js', 'function {').unsupported.some(s => s.includes('parse errors')));
});
test('supported relative-module call graph finds a genuine static path', async () => {
  const env = await setup();
  try {
    await writeFile(path.join(env.repository, 'src/index.js'), "import { run as start } from './worker.js'; start();");
    await writeFile(path.join(env.repository, 'src/worker.js'), "import { dangerous } from 'traceguard-test-direct'; export function run(){ dangerous(); }");
    const scan = await env.scanner.scan(env.repository, 'repository'); const direct = scan.findings.find(f => f.direct)!;
    assert.equal(direct.reachability.status, 'REACHABLE'); assert.ok(direct.reachability.paths[0].some(p => p.includes('worker.js#run')));
  } finally { await env.cleanup(); }
});
test('dead function is NOT_REACHABLE only in supported closed application model', async () => {
  const env = await setup();
  try {
    await writeFile(path.join(env.repository, 'src/index.js'), "import { dangerous } from 'traceguard-test-direct'; function unused(){ dangerous(); }");
    const closed = await env.scanner.scan(env.repository, 'repository'); assert.equal(closed.findings.find(f => f.direct)!.reachability.status, 'NOT_REACHABLE');
    await writeFile(path.join(env.repository, 'src/index.js'), "import { dangerous } from 'traceguard-test-direct'; function unused(){ dangerous(); } import(process.env.PLUGIN);");
    const dynamic = await env.scanner.scan(env.repository, 'repository'); assert.equal(dynamic.findings.find(f => f.direct)!.reachability.status, 'UNKNOWN');
  } finally { await env.cleanup(); }
});
