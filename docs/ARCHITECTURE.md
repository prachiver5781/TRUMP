# Architecture

```text
Codex / official MCP client
  -> STDIO transport (official @modelcontextprotocol/sdk)
  -> Zod-validated tool handlers and bounded output formatter
  -> session scanner
       -> authorization / bounded filesystem reads / safe ZIP extraction
       -> npm lockfile graph
       -> OSV exact-version batches -> full advisory hydration -> deduplication
       -> TypeScript compiler AST -> application call graph -> reachability
       -> impact paths / verified remediation / before-after comparison
       -> CycloneDX artifacts
       -> versioned TTL caches
```

## Modules

| Directory | Responsibility |
| --- | --- |
| `src/server` | Environment configuration, tool registration, STDIO lifecycle |
| `src/engine` | Authorized scan orchestration, session snapshots, ZIP handling |
| `src/dependency` | Lockfile v1/v2/v3 resolution, parent/child graph, paths |
| `src/vulnerability` | OSV requests, schema validation, range checks, aliases |
| `src/analysis` | AST import/call extraction and bounded graph traversal |
| `src/remediation` | Advisory fix candidates, OSV rechecks, fix comparison |
| `src/reports` | CycloneDX JSON generation |
| `src/cache` | Hashed, versioned cache entries, TTL and invalidation |
| `src/utils` | Path containment, bounded reads, errors, pagination/output caps |

## Data flow and evidence

1. Host configuration supplies an immutable allowlist of absolute directories.
   Initial tool calls also require `authorized: true`, representing explicit
   user consent. A tool argument cannot grant access outside the allowlist.
2. The scanner reads the root manifest and lockfile without running npm. Locked
   entries are package instances identified by installation location; repeated
   names/versions retain their distinct parents/children. npm aliases use the
   resolved `name` when supplied by the lockfile.
3. OSV receives unique npm names and exact versions in batches of at most 100.
   `/querybatch` returns IDs/modified timestamps; the client fetches full records
   from `/vulns/{id}` with at most six concurrent hydrations. Per-query OSV
   pagination is followed to completion or explicitly becomes incomplete.
4. Withdrawn records are excluded. Supported npm version ranges are checked
   locally; unsupported ranges retain OSV's exact-version match, rather than
   fabricating a negative result. Alias-connected advisories are deduplicated
   per package/version. Every finding retains its original advisory records.
5. Source is parsed locally by the TypeScript compiler. Imported bindings use
   compiler symbols so ordinary parameter shadowing does not create a false
   imported-function call. Function graphs include supported local and relative
   module calls. No source file is sent to a model or OSV.
6. Advisory `affected[].ecosystem_specific.affected_functions` is the only source
   of vulnerable export names. A recognized static path yields REACHABLE;
   unsupported/missing evidence yields UNKNOWN. Negative results require the
   supported closed model. Package relationships are reported separately.
7. A compact immutable scan snapshot is retained in memory. Full source text is
   not retained. Snippets require another authorized read and matching source
   hash. ZIPs are re-extracted only if a snippet is explicitly requested.

## Caches and incremental scans

- Dependency graph: tool version + complete manifest hash + lockfile hash.
- Per-file AST facts: analyzer version + relative file path + source hash.
- OSV queries: exact package/version + freshness TTL. Advisory records also use
  ID/modified timestamp. Query cache timestamps preserve the oldest observation
  represented by a scan's `checked_at`.
- SBOM: tool version + lockfile hash + selected manifest metadata.
- Scan fingerprint: tool version, manifest/lockfile hashes, sorted file paths and
  content hashes. File deletion and entry-point changes alter the fingerprint.

Every source file is hashed each scan. Only changed ASTs are reparsed; the
inter-file graph and reachability are rebuilt to account for changed edges.
Lockfile or manifest changes regenerate the graph. Unchanged exact versions may
reuse fresh OSV results. `refresh_advisories: true` bypasses all scan caches;
`verify_fixes` always forces fresh checks. TTL expiry/corrupt cache entries cause
a miss. `CacheStore.invalidate(namespace, key)` supports targeted invalidation.
Version 0.1.1 invalidates prior caches and validates cache envelopes and cached
OSV records. Partial advisory hydration retains successfully retrieved findings
and marks the package unchecked; incomplete responses are never cached as clean.

## Lifecycle and resources

One scan runs at a time; concurrent scans receive BUSY. Queries against completed
snapshots remain available. At most 20 scan snapshots are retained. An unknown or
evicted scan ID fails explicitly. HMAC cursors are tied to a session, scan and
query; they cannot be transferred to another server process or output mode.
ZIP extraction is removed in `finally`, including scan failures. Artifacts and
caches intentionally remain available after shutdown. STDIO closes on EOF,
SIGINT or SIGTERM; extraction already in progress can finish its bounded cleanup.

No web server, arbitrary command execution, remote AI request, or automatic
project modification exists in the runtime scanning engine.
