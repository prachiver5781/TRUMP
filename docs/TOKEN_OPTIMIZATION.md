# Response efficiency

TRACEGUARD performs deterministic work locally. The conversation gets summaries
and targeted evidence rather than repositories, entire lockfiles or dependency
trees. OSV provides intelligence; no external LLM is used by the scanner.

## Defaults

- `mode: summary`: dependency totals, severity totals, critical preview,
  reachability totals, intelligence completeness, risk explanation and metrics.
- At most 10 findings per page, configurable through
  `TRACEGUARD_MAX_FINDINGS` (1–100), or per request with `page_size`.
- Maximum serialized tool-result size: 16,000 bytes; configurable with
  `TRACEGUARD_MAX_OUTPUT_BYTES` (2,048–100,000).
- Small text marker plus one JSON `structuredContent` object. JSON is not
  duplicated into the text block. Consuming clients must expose structured MCP
  results. No full source is returned by default in any output mode.

Standard mode adds small finding descriptions; detailed mode adds evidence
metadata. Full records and narrowly bounded snippets have separate tools.
Dependency nodes, findings, reachability paths, impact paths and remediation are
paginated. A signed cursor includes the scan/query/mode and the next offset.

Page construction reduces rows to fit the byte budget, retaining an explicit
next cursor. If a single row or requested detail is too large, the complete
requested response is written as a local artifact and an explicit truncation
record points to it. Findings are not silently dropped: severity/total counts
remain available, and warning previews report omitted-warning counts. Detailed
summary mode exposes all warnings, subject to the artifact fallback.

## Avoid repeated work

Content hashes drive per-file incremental AST caching. Lockfile/manifest hashes
drive graph invalidation. Exact-version OSV results use a configurable TTL
(default one hour), full advisory caches include modified timestamps, and SBOMs
are cached by resolved graph identity. Force refresh and fix verification bypass
scan caches. Call graphs are rebuilt after changed source to avoid stale edges.

## Metrics

Scan summaries include files examined, observed non-source files/symlinks skipped,
ignored directories skipped, number of lock-resolved dependency instances,
advisory records fetched, cache hits/misses, AST files analyzed/reused, findings
returned and serialized response bytes. Skipped subtree descendants are not
counted because they are never enumerated. Bytes exclude JSON-RPC framing and
transport overhead. The `response_bytes` value includes the size field itself.
`osv_requests` counts actual HTTP attempts, including batch queries, record
hydration and retries. Warm live scans verified this counter stayed at zero.

`checked_at` is the oldest OSV query observation represented by the scan's cache
hits, or the current attempt time when none succeeded. Always read it alongside
`vulnerability_status`. A complete query is not a guarantee of vulnerability
database completeness or real-world safety.

Run:

```sh
npm run measure
```

This writes [efficiency-results.json](efficiency-results.json), with real byte
measurements of synthetic offline fixture responses in all three modes. The
first request is cold; subsequent requests reuse fresh caches. The live test
also prints actual OSV/STDIO response measurements. There is no claim of exact
model-token savings: tokenization and client presentation must be measured by
the consuming client.
