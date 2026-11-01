import path from 'node:path';
import os from 'node:os';
import { realpathSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2); const roots = [];
for (let index = 0; index < args.length; index++) {
  if (args[index] !== '--allow' || !args[index + 1]) throw new Error('Usage: node scripts/codex-config.mjs --allow /absolute/authorized/directory [--allow ...]');
  const input = args[++index];
  if (!path.isAbsolute(input)) throw new Error('Authorized directories must be absolute.');
  const resolved = realpathSync(input); if (!statSync(resolved).isDirectory()) throw new Error('Authorized root must be a directory.');
  roots.push(resolved);
}
if (!roots.length) throw new Error('At least one explicit --allow directory is required.');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dataDir = process.platform === 'darwin' ? path.join(os.homedir(), 'Library', 'Caches', 'traceguard-mcp') : path.join(os.tmpdir(), 'traceguard-mcp');
const toml = `[mcp_servers.traceguard]
command = ${JSON.stringify(process.execPath)}
args = [${JSON.stringify(path.join(root, 'dist', 'server', 'index.js'))}]
startup_timeout_sec = 20
tool_timeout_sec = 180

[mcp_servers.traceguard.env]
TRACEGUARD_ALLOWED_ROOTS = ${JSON.stringify(JSON.stringify(roots))}
TRACEGUARD_DATA_DIR = ${JSON.stringify(dataDir)}
TRACEGUARD_MAX_OUTPUT_BYTES = "16000"
TRACEGUARD_MAX_FINDINGS = "10"
TRACEGUARD_OSV_TTL_SECONDS = "3600"
TRACEGUARD_OSV_TIMEOUT_MS = "15000"
`;
process.stdout.write(toml);
