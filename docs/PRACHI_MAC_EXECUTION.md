# Prachi: Mac execution and Codex MCP check

**Not executed on macOS.** Open Terminal in the TRACEGUARD project folder (where
`package.json` is). Use zsh or bash with Node.js 22+ and the Codex CLI installed.
These commands find actual paths without assuming a username/Homebrew prefix.

## Build and prepare the existing real npm test repository

```sh
node --version
npm --version
codex --version
npm ci --ignore-scripts
npm run build
npm run validate:prepare

TRACEGUARD_PROJECT="$(pwd -P)"
TRACEGUARD_NODE="$(command -v node)"
TRACEGUARD_SCAN_ROOT="$(node -p 'JSON.parse(require("fs").readFileSync("docs/validation-inputs.json", "utf8")).repositories[0].directory')"
TRACEGUARD_ALLOWED_ROOTS="$(node -p 'JSON.stringify([process.argv[1]])' "$TRACEGUARD_SCAN_ROOT")"
printf 'Project: %s\nNode: %s\nAuthorized repository: %s\n' "$TRACEGUARD_PROJECT" "$TRACEGUARD_NODE" "$TRACEGUARD_SCAN_ROOT"
```

Preparation uses real npm metadata and package-lock-only with scripts disabled.
It does not install target dependencies or run the test app. Stop if a command
fails. The prepared input contains express 4.17.1, lodash 4.17.20 and is-number
7.0.0; it is deliberately used to check vulnerability reporting.

## Register the compiled server

```sh
codex login status
```

If unauthenticated, run `codex login` and complete sign-in. If an existing
`traceguard` entry needs preserving, inspect `codex mcp get traceguard` first.
The next command registers it in Prachi's current configuration and explicitly
authorizes only the prepared repository:

```sh
codex mcp add traceguard \
  --env "TRACEGUARD_ALLOWED_ROOTS=$TRACEGUARD_ALLOWED_ROOTS" \
  --env "TRACEGUARD_DATA_DIR=$HOME/Library/Caches/traceguard-mcp" \
  --env 'TRACEGUARD_MAX_OUTPUT_BYTES=16000' \
  --env 'TRACEGUARD_MAX_FINDINGS=10' \
  --env 'TRACEGUARD_OSV_TIMEOUT_MS=15000' \
  -- "$TRACEGUARD_NODE" "$TRACEGUARD_PROJECT/dist/server/index.js"

codex mcp get traceguard --json
codex mcp list
```

Transport must be `stdio`, command the actual Node path, and the script argument
the absolute `dist/server/index.js` path. Do not use `npm start` as the MCP command.
`node scripts/codex-config.mjs --allow "$TRACEGUARD_SCAN_ROOT"` also prints an
exact TOML configuration with persistent startup/tool timeouts if needed.

## Invoke the registered server through actual Codex

```sh
mkdir -p .traceguard
set -o pipefail

TRACEGUARD_PROMPT="Use only TRACEGUARD MCP tools. Do not use shell, filesystem, browser or other servers' tools. I explicitly authorize a read-only scan of $TRACEGUARD_SCAN_ROOT. First call scan_repository with repository_path set to that exact path, authorized true, mode summary, and refresh_advisories true. Then call check_vulnerabilities with the actual returned scan_id, mode summary, page_size 2 and no cursor. Call check_vulnerabilities again with the same scan_id, mode summary, page_size 2 and the actual next_cursor from the first findings page. Do not request snippets or read source files yourself. Never invent IDs or results. If tools are unavailable, report failure. Return compact JSON with execution_success, scan_id, dependency/finding counts, summary_response_bytes, first_page_finding_ids, second_page_finding_ids and whether more findings remain. UNKNOWN reachability does not prove safety."

printf '%s\n' "$TRACEGUARD_PROMPT" | codex exec \
  --skip-git-repo-check --ephemeral --sandbox read-only --json \
  -c 'mcp_servers.traceguard.startup_timeout_sec=20' \
  -c 'mcp_servers.traceguard.tool_timeout_sec=180' \
  -C "$TRACEGUARD_PROJECT" \
  -o .traceguard/prachi-codex-final.json - \
  | tee .traceguard/prachi-codex-events.jsonl

printf 'Codex pipeline exit status: %s\n' "$?"
cat .traceguard/prachi-codex-final.json
```

Success requires zero exit status and three completed `mcp_tool_call` events on
server `traceguard`: one scan and two findings calls. Both findings calls must
use the scan's actual ID; the second must use the first page's real cursor and
return different finding IDs. Source files must not appear in the results.
Counts may change with OSV. A model's prose success claim alone is insufficient.

For interactive discovery, start `codex` and inspect `/mcp`; TRACEGUARD should
expose all eleven tools. Existing IDE/app sessions need restarting to load the
entry. Mac runtime, authentication, startup, network, tool invocation and the
separate IDE/app UI remain unverified until executed on Prachi's machine.
