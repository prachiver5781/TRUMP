# In-chat security reports

`generate_security_report` is the preferred tool for a user-authorized repository
path. It returns Markdown directly in MCP text content for Codex to display in
chat. There is no HTML dashboard, webpage, report file or UI server. All eleven
original tools, schemas, pagination and authorization rules remain available.
Restart the MCP server/connection after building to load the new tool list and
server instructions. This repository does not modify global Codex settings.

## Calls

Initial report, inside server-configured allowed roots:

```json
{"repository_path":"C:/Users/alice/projects/app","authorized":true}
```

Follow-up using a session-local snapshot, with no source reads:

```json
{"scan_id":"<UUID from the report>"}
```

Provide exactly one path or scan ID. A path always requires `authorized: true`.
Optional arguments: `include_fixes` (default true), `refresh_advisories` (false),
and `time_budget_ms` (1000–110000, default 105000). Refreshing requires the
authorized path; it cannot silently refresh an old snapshot. Disabling fixes
returns immediately after the scan without asserting patched versions.

For ZIPs, first use the preserved `scan_zip` tool and then pass its scan ID to
the report tool. Both initial repository and ZIP tools remain read-only.

## Seven report sections

1. Security overview: score/level, unique dependency names, direct/transitive
   counts, vulnerable package names and unique vulnerability identities.
2. Vulnerability counts: Critical/High/Medium/Low/Unknown, distinct OSV record
   IDs, unique CVE IDs and aggregated reachability states.
3. Four compact Markdown text-bar charts: total/vulnerable dependencies,
   severity, OSV records/CVEs and reachability. Bars are relative to each chart's
   maximum; numeric labels provide the exact counts.
4. Top five issues: one representative package/version per unique issue,
   severity, supplied advisory/CVE IDs, advisory summary, static evidence and fix.
5. How to fix: only advisory-reported versions excluded by affected ranges AND
   returning no known OSV matches may get commands. Direct dependency commands
   preserve dev/optional/runtime classification and use `--ignore-scripts`.
   Transitive parent versions are never invented. Publication, compatibility and
   unknown defects are not verified. No command is executed by the scanner.
6. Coverage: supported ecosystems, files analyzed/examined, unsupported detected
   components, incomplete work, errors/timeouts, cache statistics and timestamps.
7. Verdict: risk, three actions and whether manual review is required.

The default output budget is 16000 bytes for the entire MCP result, not just the
Markdown. Detail levels shrink to fit smaller configured budgets. `truncated`
and an inline notice disclose omitted charts/evidence/warnings. Counters use
all available results, independent of the top-five display. Continue with the
existing finding/detail/remediation tools when needed. Unlike their artifact
fallback, this tool never creates an external report.

## Counting rules

- Dependency totals count **unique package names**, excluding the project root.
  A name with both direct and transitive locations is counted direct once.
  Structured counters also expose unique name/version components and lockfile
  location counts. “Installed version” in findings means lock-resolved version;
  the actual runtime environment is not verified.
- Vulnerable dependencies count unique affected package names, independent of
  their versions, locations or number of advisories.
- Unique issues merge connected OSV IDs and aliases globally, including bridge
  aliases across multiple packages/versions. Severity uses the highest known
  severity in the group. CVE IDs are deduplicated separately.
- OSV advisory count is the number of distinct **returned record IDs**, not
  alias groups. OSV record and CVE counts are different units and never summed.
- Reachability counts use the same unique issue groups as severity counts. A
  group is REACHABLE if any instance is reachable, otherwise UNKNOWN if any is
  unknown, otherwise NOT_REACHABLE. This does not prove exploitation or safety.

## Risk score

This is an explained dependency triage index, not a calibrated estimate of
exploit probability or a score for unanalyzed application security:

`min(100, highest severity weight + reachability bonus + package breadth)`

- Highest severity weight: Critical 80, High 60, Medium 30, Low 10, Unknown 30.
- Reachability bonus: +10 if any unique issue is statically reachable; +0
  otherwise. Unknown/not-reachable never subtract from a known issue's weight.
- Package breadth: +2 for each additional unique vulnerable package after the
  first, capped at +10.
- Level thresholds: Critical >=80, High >=60, Medium >=30, otherwise Low.
- No findings plus complete supported checks = 0/Low for observed dependencies,
  with an explicit no-safety-guarantee statement.
- No findings plus incomplete/unsupported checks = UNKNOWN, with no numeric
  score. Known findings with incomplete checks are a provisional lower bound.
  Unknown severity also marks the score provisional and requires manual review.

## Performance and limitations

The default 105-second budget aims to leave room within a two-minute demo for
the client and final chat rendering. Up to 25 seconds is reserved for the top
five fix checks. File traversal and AST analysis stop cooperatively; one
synchronous parse or slow filesystem operation can exceed the target, so this
is a best-effort budget, not a real-time guarantee. Reachability checks also
check a wall-clock deadline between findings.

Independent source analysis and OSV queries run concurrently. OSV batches
deduplicate name/version queries; advisory hydration has a six-request ceiling
and shares each record within a query. Top-five fix candidates are verified in
one deduplicated batch. Existing graph, per-file AST, OSV query and advisory
caches are reused; `scan_id` avoids a rescan. Warm reports need no duplicate OSV
requests while cached results remain fresh. Forced refresh intentionally
bypasses intelligence caches. Timed-out or incomplete queries are never cached
as clean complete results.

Only npm lockfile versions 1–3 and the existing JS/TS AST model are supported.
Unsupported projects return an UNKNOWN report after bounded authorized metadata
discovery, with no guessed dependency counts or source execution. Mixed
ecosystem files are counted and labelled unsupported. This is not a generic
SAST, secret, infrastructure, malware or runtime exploit scanner. No registry
publication check or complete dependency-internal call graph is claimed.

Reports omit source snippets, escape and bound untrusted labels/advisory text,
and preserve source/output/archive limits. Only the scanner's external cache
directory is written. STDOUT remains exclusively MCP messages.
