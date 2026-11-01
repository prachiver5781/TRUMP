# MCP tools

All tools advertise Zod-derived input JSON Schemas, descriptions, annotations
and a structured output schema. Tool results contain `structuredContent` and a
small text marker, avoiding a second full copy of the JSON. The new
`generate_security_report` instead returns Markdown in the text content, with
compact structured counters; it never spills to a file. Errors have
`isError: true` and an `error: { code, message }` when handled by the application;
SDK schema validation errors are also MCP tool errors.

All successful and application error results have `truncated` and
`metrics.response_bytes` (serialized CallToolResult bytes, excluding JSON-RPC
framing). `metrics.findings_returned` counts finding rows in that response.
Oversized payloads from the original tools become local artifacts with an
explicit omission reason. The chat report abbreviates in place and discloses
omissions while retaining its seven headings.

## Common arguments

| Argument | Meaning |
| --- | --- |
| `scan_id` | UUID returned by a scan, valid only in that server session |
| `mode` | `summary` (default), `standard`, `detailed` |
| `page_size` | Integer 1–100, default `TRACEGUARD_MAX_FINDINGS` (10) |
| `cursor` | Opaque `next_cursor` from the same scan/query/mode/session |
| `authorized` | Literal `true`; only after explicit user authorization |

The output byte budget may reduce a page below its requested size. Continue
until `next_cursor` is absent. A page can also report analysis truncation
separately from response pagination (for example `paths_analysis_truncated`).

## 1. scan_repository

Required: `repository_path` (absolute), `authorized`. Optional: `mode`,
`refresh_advisories` (default false). Requires root `package.json` and
`package-lock.json`.

Returns `scan_id`, `project_name`, dependency counts, `vulnerability_counts`,
`vulnerability_status`, `critical_findings`, `reachability_summary`, `risk_summary`,
warning counts, `truncated`, a findings cursor when needed and internal metrics.
Summary mode previews only critical findings; HIGH/MEDIUM/LOW/UNKNOWN counts
remain visible and their findings are retrieved with `check_vulnerabilities`.
`standard` and `detailed` include a bounded findings preview.

```json
{"repository_path":"/Users/alice/projects/app","authorized":true,"mode":"summary"}
```

## 2. scan_zip

Required: `zip_path` (absolute), `authorized`. Optional: `mode`,
`refresh_advisories`. Returns the same summary as `scan_repository`.

```json
{"zip_path":"/Users/alice/projects/app.zip","authorized":true}
```

## 3. generate_sbom

Required: `scan_id`. Optional: `format` (only `CycloneDX`). Returns
`format`, `spec_version`, `components`, `artifact_path`. Uses the scan snapshot
without re-reading the target repository.

## 4. check_vulnerabilities

Required: `scan_id`. Optional: `mode`, `page_size`, `cursor`. Returns paginated
`items`, `total_items`, `returned_items`, `truncated`, `next_cursor` and the
snapshot's intelligence status/time. It retrieves already checked findings.
Rescan with `refresh_advisories: true` to refresh intelligence.

```json
{"scan_id":"<scan UUID>","page_size":5,"mode":"standard"}
```

## 5. get_dependency_graph

Required: `scan_id`. Optional: `mode`, `page_size`, `cursor`. Summary nodes expose
IDs, names, exact versions, direct flags and relationship counts. Standard nodes
add parents/children/dev/optional; detailed adds location/integrity when present.
The root is reported separately, with ID `root`.

## 6. analyze_reachability

Required: `scan_id`. Optional: `finding_id`, `mode`, `page_size`, `cursor`,
`view` (`findings` default, or `paths`). Each result has a status and explanation.
Standard/detailed include file/line evidence and advisory-provided symbols.
`view: "paths"` requires `finding_id` and paginates the actual call-path arrays.

```json
{"scan_id":"<scan UUID>","finding_id":"<finding ID>","view":"paths","page_size":5}
```

## 7. get_impact_analysis

Required: `scan_id` and at least one of `finding_id`, `dependency_id`. Optional:
`page_size`, `cursor`. Returns immediate parents/children and reverse dependent ancestors, separate
security-impact status, and paginated root-to-target dependency paths. If both
selectors are supplied the finding takes precedence. Cycles are bounded and
path enumeration is capped at 1,000 paths / 20,000 traversal steps / depth 128;
`paths_analysis_truncated` discloses that limit.

## 8. generate_remediation_plan

Required: `scan_id`. Optional: `page_size`, `cursor`, `refresh_advisories`.
Uses only advisory fixed events and checks up to eight candidates per finding
against OSV. A `verified_unaffected_version` must also fall outside the original
supported affected ranges; verification is limited to known current OSV data.
Returns commands only for verified direct updates. Commands include
`--ignore-scripts`, exact pins, dependency classification and `--` before the
package argument. Transitive updates require parent/override review.
No commands are executed and no target files are changed.

## 9. verify_fixes

Required: `previous_scan_id`, `authorized`. Optional: `repository_path` or
`zip_path` (at most one). With no new path, rescans the previous source. New paths
are allowlist-checked and project names must match. Fresh OSV queries compare
alias-connected advisory identities across versions. Returns resolved,
remaining, newly detected and unverified finding IDs, plus the new `scan_id`.
Unavailable/partial scans cannot verify absent old findings as resolved.

## 10. get_scan_summary

Required: `scan_id`. Optional: `mode`. No source reads or network requests.
Detailed mode exposes the complete warnings (an artifact if they exceed the
byte budget), fingerprint and entry points.

## 11. get_finding_details

Required: `scan_id`, `finding_id`. Optional: `include_snippet` (default false),
`evidence_index` (default 0), `snippet_lines` (1–10, default 8). Returns original
advisories, CVEs, affected ranges, fix events, references and reachability evidence.
An explicitly requested snippet is limited to the selected evidence's file/line,
at most 10 lines and 4,000 characters. Comments/literals are masked. It fails if
the source hash changed; it never accepts an arbitrary snippet file path.

```json
{"scan_id":"<scan UUID>","finding_id":"<finding ID>","include_snippet":true,"evidence_index":0,"snippet_lines":5}
```

## 12. generate_security_report

Preferred for automatic, presentation-ready **in-chat** reports. Provide exactly
one `repository_path` or existing `scan_id`. A path requires `authorized: true`.
Optional: `include_fixes` (true), `refresh_advisories` (false; path only), and
`time_budget_ms` (1000–110000; default 105000).

Returns seven Markdown sections in `content[].text`, with compact
`structuredContent` counters and metrics. Includes four text-bar charts, global
advisory/CVE deduplication, an explained priority score, top five findings,
verified fix suggestions and explicit coverage limitations. No report/dashboard
file or webpage is generated. Output limits abbreviate the inline display with
`truncated: true`; counts still cover all available results. The original tools
remain available for additional findings and evidence.

```json
{"repository_path":"/Users/alice/projects/app","authorized":true}
```

Reuse the returned `scan_id` on follow-up calls to avoid re-reading source.
For unsupported ecosystems or missing npm lockfiles, the tool returns an
incomplete UNKNOWN report instead of fabricated counts. Authorization failures
remain MCP errors. See [CHAT_REPORT.md](CHAT_REPORT.md) for scoring/counting
rules, the best-effort time budget and safety limitations.
