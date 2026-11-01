# Codex setup (macOS and Windows)

The configuration uses the official Codex STDIO MCP settings, verified against
[OpenAI's MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
and the installed CLI's `codex mcp add --help`. CLI and IDE extension share MCP
configuration in `~/.codex/config.toml`. No OpenAI API key is required by
TRACEGUARD itself; it calls only OSV over HTTPS.

## macOS: install

Use Node.js 22 or later. In the project directory:

```sh
npm ci --ignore-scripts
npm run build
npm test
npm run test:live
command -v node
```

Do not use a guessed Node path. Homebrew often uses `/opt/homebrew/bin/node`
on Apple Silicon or `/usr/local/bin/node` on Intel; nvm uses a versioned path.
The following concrete example assumes the checkout is
`/Users/alice/TRACEGUARD-MCP` and the authorized repository area is
`/Users/alice/projects`. Substitute your actual paths, or run the generator below.

## macOS: config.toml

```toml
[mcp_servers.traceguard]
command = "/opt/homebrew/bin/node"
args = ["/Users/alice/TRACEGUARD-MCP/dist/server/index.js"]
startup_timeout_sec = 20
tool_timeout_sec = 180

[mcp_servers.traceguard.env]
TRACEGUARD_ALLOWED_ROOTS = '["/Users/alice/projects"]'
TRACEGUARD_DATA_DIR = "/Users/alice/Library/Caches/traceguard-mcp"
TRACEGUARD_MAX_OUTPUT_BYTES = "16000"
TRACEGUARD_MAX_FINDINGS = "10"
TRACEGUARD_OSV_TTL_SECONDS = "3600"
TRACEGUARD_OSV_TIMEOUT_MS = "15000"
```

TOML does not expand `~`, `$HOME` or environment variables inside these paths.
This prints a ready-to-paste configuration using your actual checkout and Node
executable; it validates the explicitly chosen authorized directory:

```sh
node scripts/codex-config.mjs --allow "$HOME/projects"
```

Repeat `--allow /absolute/directory` for additional explicitly authorized roots.
Use narrowly scoped roots. The generator prints configuration; it does not
modify your global Codex settings.

## macOS: CLI equivalent

```sh
codex mcp add traceguard \
  --env 'TRACEGUARD_ALLOWED_ROOTS=["/Users/alice/projects"]' \
  --env 'TRACEGUARD_DATA_DIR=/Users/alice/Library/Caches/traceguard-mcp' \
  --env 'TRACEGUARD_MAX_OUTPUT_BYTES=16000' \
  -- /opt/homebrew/bin/node /Users/alice/TRACEGUARD-MCP/dist/server/index.js
codex mcp list
codex mcp get traceguard
```

The CLI creates the server entry and environment; set `tool_timeout_sec = 180`
in `config.toml` for larger scans (CLI defaults may be shorter). Launch a new
Codex session, or restart the IDE extension, and use `/mcp` in the CLI to inspect
the tools. Tool discovery should show eleven tools.

## Windows

```powershell
npm.cmd ci --ignore-scripts
npm.cmd run build
node scripts/codex-config.mjs --allow 'C:\Users\alice\projects'
```

Paste the generated TOML into `%USERPROFILE%\.codex\config.toml`. The generated
config uses a fully qualified `node.exe` path and correctly escaped Windows
paths. [codex.windows.toml](codex.windows.toml) contains exact paths for the
workspace used to build this project. Update it if the checkout is moved.

## First invocation and failure handling

After explicitly authorizing a repository, ask Codex to call:

```json
{"repository_path":"/Users/alice/projects/my-app","authorized":true,"mode":"summary"}
```

- `PATH_DENIED`: the real path is outside configured roots (including symlinks).
- `PROJECT_NOT_FOUND`: readable manifest/lockfile pair is missing.
- `vulnerability_status: "partial"` or `"unavailable"`: retry with
  `refresh_advisories: true`; do not treat missing findings as safety evidence.
- `SCAN_NOT_FOUND`: rescan after a restart or snapshot eviction.
- `INVALID_CURSOR`: use a cursor from the same session, tool query and mode.
- Startup timeout: verify Node and the compiled absolute script path, allowed
  roots and data-directory permissions. The server intentionally has no stdout
  startup banner; errors go to stderr.

Validation includes official SDK clients and the compiled server over STDIO,
including real repository and ZIP scans against OSV. The separate integration
round also verified an actual Windows Codex CLI scan and two findings calls;
see [CODEX_EXECUTION.md](CODEX_EXECUTION.md). macOS and IDE/app UI execution
remain unverified. [Prachi's exact Mac commands](PRACHI_MAC_EXECUTION.md) are
provided for her machine. No exact model-token savings are claimed.
