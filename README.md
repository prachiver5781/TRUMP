# TRACEGUARD MCP

A local, evidence-backed npm supply-chain scanner for OpenAI Codex. Built with
TypeScript, Node.js and the official Model Context Protocol SDK. The product is
an STDIO MCP server. There is no frontend and no LLM inside the scanning engine.

TRACEGUARD reads lock-resolved versions, queries the real OSV API, builds an AST
call graph locally, and returns bounded structured results. It never installs or
executes the target project's code and never applies fixes.

## Install and run

Requires Node.js 22+ and npm. From this directory:

```sh
npm ci --ignore-scripts
npm run build
npm test
npm run test:live
```

On Windows PowerShell, use `npm.cmd` if script execution policy blocks `npm.ps1`.
The live test requires HTTPS access to `api.osv.dev`. Offline tests use explicitly
labeled synthetic fixtures; those fixtures are never a production fallback.
`npm test` expects the compiled server from `npm run build`.

Authorize paths through the **server environment**, not MCP arguments:

```sh
export TRACEGUARD_ALLOWED_ROOTS='["/Users/alice/projects"]'
node /absolute/path/to/TRACEGUARD-MCP/dist/server/index.js
```

The process waits for MCP messages on stdin. Empty/missing roots fail closed.
Copy `.env.example` to `.env` in the server's project folder to configure manual
startup. Only that trusted server-local file is loaded; scanned projects' `.env`
files are ignored. Explicit process/Codex settings take precedence. Allowed roots
must exist and be accessible; filesystem/drive roots are rejected.
Set `TRACEGUARD_DATA_DIR` outside all authorized scan roots (for example,
`C:/Users/rajpu/AppData/Local/TRACEGUARD/data` on this Windows machine).
The server rejects overlapping storage paths before creating any directories,
including aliases through symlinks/junctions. Caches, SBOMs, oversized reports
and ZIP extraction files stay in this external data directory.
Use the compiled `node` command in MCP configuration; `npm start` writes an npm
banner on stdout unless run with `--silent`.

## Connect Codex

Generate a configuration with exact absolute paths for the current machine:

```sh
node scripts/codex-config.mjs --allow /Users/alice/projects
```

Paste its output into `~/.codex/config.toml`. Alternatively:

```sh
codex mcp add traceguard --env 'TRACEGUARD_ALLOWED_ROOTS=["/Users/alice/projects"]' -- /opt/homebrew/bin/node /Users/alice/TRACEGUARD-MCP/dist/server/index.js
codex mcp list
```

See [macOS and Windows setup](docs/CODEX_SETUP.md) for complete configurations,
CLI setup, PATH handling and verification. A generated workspace-specific
Windows configuration is supplied in [docs/codex.windows.toml](docs/codex.windows.toml).
This project does not automatically change the user's global Codex configuration.

## First scan

Tell Codex: “I authorize scanning `/Users/alice/projects/my-app` with TRACEGUARD.
Return the security report directly in chat, with Markdown charts and no dashboard.”

Call `generate_security_report` with:

```json
{"repository_path":"/Users/alice/projects/my-app","authorized":true}
```

This one call runs the available checks and returns seven presentation-ready
Markdown sections, text-bar charts, deduplicated counts, an explained priority
score, the top five issues, verified fix suggestions and coverage gaps. It never
creates an HTML report or separate webpage. Follow-ups can pass only `scan_id`
to reuse the snapshot. See [chat report details](docs/CHAT_REPORT.md).

The original `scan_repository` compact summary remains available. Use
`check_vulnerabilities` with its returned `scan_id`, `page_size: 5` and optionally
`next_cursor` as `cursor` for additional findings. Preserve the same `mode` when
continuing a cursor. For ZIPs use `scan_zip` with `zip_path` and
`authorized: true`. ZIPs must contain `package.json` and `package-lock.json` at
the archive root or inside one top-level project folder.

The tools are documented in [MCP_TOOLS.md](docs/MCP_TOOLS.md). Source is
excluded unless `get_finding_details` specifically requests a bounded snippet.
Full SBOMs and oversized requested details from the original tools are private
local JSON artifacts. The chat report stays inline and explicitly abbreviates
its display when the output budget is too small.

## What works

- npm package-lock versions 1, 2 and 3; nested and hoisted dependency graphs,
  alias package names, dev/optional flags and unresolved-edge warnings.
- Safe repository/ZIP scanning with path authorization and resource limits.
- Real OSV batch queries, pagination, full advisory hydration, CVE aliases,
  severity/ranges/fix events/references, retries, TTL caching and partial results.
- CycloneDX 1.5 JSON SBOMs with dependency relationships and package URLs.
- TypeScript compiler AST analysis of JS/TS/JSX/TSX, ESM imports, supported
  CommonJS imports, local functions, relative imports and direct call paths.
- Conservative function reachability when advisory metadata identifies the
  affected symbol; separate dependency impact paths.
- Advisory-backed remediation candidates, exact-version OSV rechecks and
  comparison scans that never classify an unavailable check as a verified fix.
- Incremental per-file AST caches, dependency/SBOM caches, signed pagination
  cursors, response-size caps and measured output bytes.

## Scope and limitations

This is a working first version, not a complete exploitability engine. Real
npm advisories may lack supported affected-function metadata; those findings are
`UNKNOWN`. Dependency internals, dynamic dispatch, callbacks and frameworks are
not fully modeled. `REACHABLE` means a supported static potential call path,
not a working exploit. `NOT_REACHABLE` is limited to the supported model and
never means the application is safe.

Only npm lockfiles are supported. Workspaces/local links are flagged, not followed.
No npm registry publication checks, automated edits, package installation, custom
vulnerable-function guesses, or exact model-token savings are claimed. Scans
are session-local and evicted after 20 snapshots; caches/artifacts persist in the
server-owned data directory. Read [LIMITATIONS.md](docs/LIMITATIONS.md) and
[SECURITY.md](docs/SECURITY.md) before using on untrusted repositories.

## Verification and efficiency

`npm test` checks the engine, OSV adapter, real SDK client/server initialization,
all tools, compiled STDIO discovery, security boundaries, caches and pagination.
`npm run test:live` uses actual OSV records and the compiled STDIO server.
`npm run measure` writes [measured response sizes](docs/efficiency-results.json).
`node scripts/self-scan.mjs` scans this project's own lockfile through STDIO
against OSV and writes a compact report under its external data directory's
`reports/` folder. Set `TRACEGUARD_DATA_DIR` to select that directory.

For the full live validation with registry-generated lockfiles, real repository
and ZIP inputs, all eleven tools, and the official CycloneDX schema:

```sh
npm run validate:prepare
npm run validate:live
```

Preparation retrieves npm metadata with `--package-lock-only --ignore-scripts`;
it never installs or executes the test applications. The run records tool calls,
exact byte sizes, OSV findings, graph paths and cache behavior in
[full-validation-results.json](docs/full-validation-results.json). Schema
downloads require access to CycloneDX's website or GitHub. Official SDK STDIO
compatibility is tested. An actual Windows Codex CLI scan and paginated findings
were subsequently verified; see [execution evidence](docs/CODEX_EXECUTION.md).
macOS and IDE/app UI execution remain untested. See
[Prachi's Mac commands](docs/PRACHI_MAC_EXECUTION.md) for that verification.

See [ARCHITECTURE.md](docs/ARCHITECTURE.md),
[TOKEN_OPTIMIZATION.md](docs/TOKEN_OPTIMIZATION.md), and
[VALIDATION.md](docs/VALIDATION.md) for implementation and validation details.
