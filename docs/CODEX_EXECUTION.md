# Actual Codex MCP execution

Executed on **1 November 2026**, Windows: Node.js **24.15.0**, npm **11.12.1**,
Codex CLI **0.164.0-alpha.11.1** (installed VS Code extension binary), and rebuilt
TRACEGUARD **0.1.1**. No production source, architecture, dependency or feature
changes were made in this integration round.

## Current registration

TRACEGUARD was added using `codex mcp add` to
`C:\Users\rajpu\.codex\config.toml`. The entry is enabled, uses STDIO and the
absolute Node executable/script paths, authorizes only this workspace, and sets
startup/tool timeouts to 20/180 seconds. Other entries were preserved.
[codex-registration.json](codex-registration.json) contains actual CLI readback;
[codex.windows.toml](codex.windows.toml) mirrors that configuration.

The sandboxed CLI initially could not resolve its home directory. The normal
user environment resolved it and reported an existing ChatGPT login. No
HOME/CODEX_HOME override or sandbox bypass was used. The actual Codex execution
selected its `read-only` shell sandbox.

## Execution evidence

[codex-stdio-probe.json](codex-stdio-probe.json) records a fresh STDIO handshake
and all **11 discovered tools**. That SDK probe is separate from the actual
Codex execution in [codex-execution-results.json](codex-execution-results.json).

The real CLI used its registered MCP entry and existing ChatGPT login:

```text
codex exec --skip-git-repo-check --ephemeral --sandbox read-only --json
  -C <workspace> -o <local-final-output> -
```

Codex exited **0**, with no error/failed-turn events, and actually invoked:

| Tool | Result | Serialized Codex result bytes |
| --- | --- | ---: |
| `traceguard.scan_repository` | 52 dependencies; 20 findings; complete OSV check, 22 fresh HTTP requests | 1,429 |
| `traceguard.check_vulnerabilities` | First 2 findings; next cursor provided | 872 |
| `traceguard.check_vulnerabilities` | Next 2 distinct findings; real cursor reused | 878 |

The server reported **1,428 summary bytes**. Codex serializes
`structuredContent` as `structured_content`, adding one byte; the table measures
the Codex result objects. These are byte measurements, not token savings.

Severity counts were **0 CRITICAL, 7 HIGH, 7 MEDIUM, 6 LOW**. Reachability remained
UNKNOWN. The real scan ID was `04a04652-a04c-4783-94fa-804160cdc3c8`, valid only in
that completed session.

Mechanical checks passed: matching scan IDs, correct second-page cursor, four
distinct finding IDs, no source/snippet fields, and no source canary in results.
Only MCP and agent-message events occurred: no shell, file reading/editing or
browser tools. Codex's final JSON matched the actual tool payloads.

## Remaining verification

This proves the current **Windows Codex CLI** path. A restarted VS Code/desktop
UI session, macOS, Node.js 22 and other client versions were not tested. The
already-open chat may need a new session to load the newly registered server.

[PRACHI_MAC_EXECUTION.md](PRACHI_MAC_EXECUTION.md) supplies exact build,
registration and invocation commands for Prachi. Those Mac commands have not
been executed here.
