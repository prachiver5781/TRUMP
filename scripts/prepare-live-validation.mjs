// Trusted validation setup only. Never called by the MCP server.
// Generates registry-backed lockfiles; no target dependencies or scripts are run.
import path from 'node:path';
import { mkdir, writeFile, access, readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const root = path.join(workspace, '.traceguard', 'validation-inputs', randomUUID());
const npmCli = process.env.npm_execpath ?? path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js');
await access(npmCli);
const repositories = [];
for (const [directory, lodash] of [['repository', '4.17.20'], ['updated-repository', '4.17.21']]) {
  const repository = path.join(root, directory); await mkdir(path.join(repository, 'src'), { recursive: true });
  const manifest = { name: 'traceguard-live-validation-app', version: '1.0.0', private: true, type: 'module', main: 'index.js', dependencies: { express: '4.17.1', lodash, 'is-number': '7.0.0' } };
  await writeFile(path.join(repository, 'package.json'), JSON.stringify(manifest, null, 2));
  await writeFile(path.join(repository, 'index.js'), "// TRACEGUARD_SOURCE_CANARY_DO_NOT_RETURN\nimport express from 'express';\nimport { render } from './src/render.js';\nconst app = express();\napp.get('/', (request, response) => response.send(render(request.query.name)));\n");
  await writeFile(path.join(repository, 'src/render.js'), "import { template } from 'lodash';\nexport function render(value) { return template(value)({}); }\n");
  execFileSync(process.execPath, [npmCli, 'install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund', '--fetch-retries=0', '--fetch-timeout=30000', '--registry=https://registry.npmjs.org', '--cache', path.join(root, 'npm-cache')], { cwd: repository, stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000 });
  const lock = JSON.parse(await readFile(path.join(repository, 'package-lock.json'), 'utf8'));
  repositories.push({ directory: repository, lodash_version: lodash, lockfile_version: lock.lockfileVersion, locked_packages: Object.keys(lock.packages).filter(Boolean).length });
}
const report = { prepared_at: new Date().toISOString(), registry: 'https://registry.npmjs.org', root, repositories, target_code_executed: false, dependency_installation: 'package-lock-only; no node_modules or lifecycle scripts' };
await writeFile(path.join(workspace, 'docs/validation-inputs.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report));
