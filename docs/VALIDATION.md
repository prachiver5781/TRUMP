# Validation record

Validated TRACEGUARD **0.1.1** on **1 November 2026**, Windows, Node.js **24.15.0**, npm **11.12.1**.
The project targets Node.js 22+, but Node.js 22 and macOS were not executed here.
Reports preserve UTC timestamps for reproducibility.

## Commands and outcomes

| Command | Outcome |
| --- | --- |
| `npm ci --ignore-scripts --fetch-retries=0 --fetch-timeout=30000 --no-audit --no-fund` | Clean lockfile installation passed; 109 packages installed, no lifecycle scripts |
| `npm run build` | Passed; executable compiled STDIO server in `dist/server/index.js` |
| `npm run typecheck` | Passed |
| `npm test` | **46 passed**, 0 failed, 0 skipped |
| `npm run test:live` | **1 passed**, 0 failed; real OSV plus compiled STDIO client |
| `npm run measure` | Three output modes measured; response byte cap verified by tests |
| `node scripts/self-scan.mjs` | Complete real OSV check, **135 lock-resolved instances**, 0 known matches |
| `node scripts/prepare-live-validation.mjs` | Two real npm-registry-generated lockfiles, each with 52 resolved packages; no application code/install scripts run |
| `node scripts/validate-live.mjs` | **13 live validation groups passed**, **50 STDIO tool invocations**, all 11 tools invoked |

## Defects found and fixed in this validation

The original 36 tests passed, but seven new regression tests initially failed.
Version 0.1.1 fixes the confirmed defects and adds ten regression tests in total:

- Added module execution edges for top-level side-effect CommonJS requires.
- Inline/conditional/nested require, indirect call/apply/bind invocation, and
  unmodeled calls to other vulnerable-package exports cannot incorrectly produce
  NOT_REACHABLE. Unsupported paths return UNKNOWN.
- Malformed cache envelopes cannot bypass expiry; cached OSV records and query
  results are validated before reuse. Prior version caches are invalidated.
- Successfully hydrated advisory records remain visible if a sibling record or
  later OSV page fails. The package stays unchecked and partial results are never
  cached as complete clean results.
- Malformed manifest/lockfile roots and invalid packages tables fail explicitly.
- Malformed affected ranges and numeric severity scores above 10 remain unknown.
- Output fallback metadata obeys the hard response cap. Hashed cursor scopes keep
  long dependency-path queries within the accepted cursor size.
- Actual HTTP attempts are measured by `osv_requests`, including retries, so a
  claimed zero-request warm scan is directly verifiable.

No mock, placeholder, advisory fixture, shell execution, or test-data fallback
was found in production `src/`. Mocked OSV fetches and synthetic package/function
metadata are confined to the explicitly labeled offline tests/fixtures. The
live validation uses genuine registry metadata and real OSV responses.

The initial dependency installation selected Zod 3.25.76. TRACEGUARD's own
live scan found an advisory, hydrated its data, and identified advisory-reported
fixed candidate 4.6.6. An exact-version OSV query verified that candidate had no
current records. The project was migrated to Zod 4.6.6 and all tests rerun. The
final self-scan reports no known OSV matches; it is not a security guarantee.

## Automated coverage

The offline suite exercises:

- Real official SDK MCP initialization, discovery, valid/invalid invocation,
  structured result schemas and all eleven tools.
- Compiled STDIO handshake, error responses, empty non-protocol stdout,
  close behavior, startup failure through stderr and configuration generation.
- Repository/ZIP scans; direct, transitive and safe synthetic dependencies;
  lockfiles v1/v2/v3; hoisted/nested versions; graph and impact paths.
- SBOM fields, unique component references, reference consistency and caching.
- OSV pagination, rate limiting, timeout/retries, unavailable/partial status,
  malformed records, version boundaries and advisory-alias deduplication.
- ESM/CommonJS imports, parameter and require shadowing, relative-module calls,
  REACHABLE/NOT_REACHABLE/UNKNOWN, unsupported constructs and AST limits.
- Remediation verification, overlapping affected ranges, correct dependency
  classification, no invented transitive upgrade, and comparison outcomes.
- Source-hash validation, explicit snippet access and masking of comments,
  string/template/regex literals.
- Cache hits, TTL expiry, invalidation, corrupt-cache recovery and incremental
  per-file reanalysis after source/dependency changes.
- Signed pagination cursors, scope/session binding, output byte limits and
  oversized-result artifact fallback.
- Allowlist boundaries/symlink escapes, ZIP traversal/symlink/collision attacks,
  compressed/expanded/count limits, extraction cleanup and no script execution.

Offline advisory/function metadata is explicitly synthetic test data, confined
to `tests/` and `fixtures/`. Production code contains no fixture/advisory fallback.

## Live evidence

[live-osv-results.json](live-osv-results.json) records an actual scan of
`lodash@4.17.20`: **5 findings** (2 HIGH, 3 MEDIUM), with real advisory/CVE
identifiers. The STDIO summary was **1,199 bytes** and contained no source files.
Reachability was UNKNOWN because supported function metadata was absent.
The historical fixed candidate for the first finding was not reported unaffected
when the current OSV recheck still returned other advisories.

[self-scan-results.json](self-scan-results.json) records this project's real
lockfile scan: **11 direct**, **124 transitive** package instances, no known
matches. Optional platform-specific lock entries explain why this can exceed
the number of packages physically installed by npm on Windows. The 137 static
warnings in that scan reflect the documented limited model; vulnerability-query
completeness is separate from static-analysis completeness.

Scan IDs and cursors in archived reports are diagnostic snapshots, not active
session credentials. New server sessions require new scans.

## Measured response sizes

[efficiency-results.json](efficiency-results.json) is an offline benchmark of
four synthetic dependencies, two findings and one application source file:

| Mode | Serialized tool-result bytes | Additional OSV requests |
| --- | ---: | ---: |
| summary (cold) | 1,387 | 3 |
| standard (warm) | 1,728 | 0 |
| detailed (warm) | 2,420 | 0 |

The summary preview returns one critical finding and an explicit cursor for the
other finding. Counts remain complete. These are byte measurements, not measured
model-token counts or a claim of exact token savings.

## Full real repository and ZIP validation

[full-validation-results.json](full-validation-results.json) records a separate
official SDK client talking to the compiled server over STDIO. Inputs and their
provenance are in [validation-inputs.json](validation-inputs.json). The local npm
projects use express 4.17.1, lodash 4.17.20 (4.17.21 in the comparison project),
and is-number 7.0.0. npm generated both real lockfiles from registry metadata
using package-lock-only and disabled scripts; target dependencies were never
installed and target code was never executed.

| Check | Exact observed result |
| --- | --- |
| MCP initialization/discovery | traceguard-mcp 0.1.1; all 11 expected tools with input/output schemas |
| Repository and fresh ZIP scans | 52 packages: 3 direct, 49 transitive; 20 findings each |
| Finding severity | 0 CRITICAL, 7 HIGH, 7 MEDIUM, 6 LOW, 0 UNKNOWN |
| Independent OSV oracle | lodash advisory/CVE IDs matched direct `/v1/query`; is-number 7.0.0 had 0 current matches |
| Finding pagination | 20 findings retrieved in 10 pages of 2; no duplicates or omissions |
| Graph pagination | 52 nodes in 18 pages of at most 3; all references valid; 84 package-to-package edges plus 3 root edges |
| Transitive impact | Actual root-to-vulnerable-package paths retrieved and checked |
| Static analysis | Real source imports, function declaration and template calls found by the TypeScript AST |
| Live reachability | **20 UNKNOWN**, 0 REACHABLE, 0 NOT_REACHABLE; no affected-function path was proven |
| SBOM | 52 components passed official CycloneDX 1.5 JSON Schema with SPDX/JSF references |
| Warm cache | 55 hits, 0 misses, **0 OSV HTTP requests**, 0 AST reparses, 2 AST files reused |
| Fresh ZIP intelligence | 22 OSV HTTP requests; counts matched repository; extraction directory empty afterward |
| Remediation | Real advisory-backed first and second pages retrieved; no commands executed |
| Fresh comparison | **2 resolved, 18 remaining, 0 new, 0 unverified** after the controlled lodash change |
| Responses | Cold summary 1,429 bytes; warm summary 1,427; ZIP summary 1,428; largest of 50 responses **5,035 bytes**, below 16,000 |
| Errors/side effects | Wrong cursor and disallowed path rejected; no target node_modules, source canary exposure or server stderr output |

CycloneDX schemas were fetched from the official website after GitHub connection
resets. Schema URLs and SHA-256 hashes are retained in the JSON report. The SDK
AJV provider ignores `iri-reference` and `idn-email` format keywords for optional
fields; the generated BOM contains no internationalized email/IRI fields. This
was a JSON Schema check, not an independent CycloneDX certification.

Reproduce with `npm run validate:prepare` then `npm run validate:live` after a
build. Preparation makes fresh controlled inputs; live tests require OSV/npm
and the schema hosts. Archived scan IDs/cursors are session-local snapshots.

## Remaining untested and incomplete behavior

The initial validation above used an official SDK client. A subsequent actual
Windows Codex CLI integration is now verified in
[CODEX_EXECUTION.md](CODEX_EXECUTION.md) and
[codex-execution-results.json](codex-execution-results.json): CLI exit 0, one
fresh repository scan and two correctly paginated findings calls. All eleven
tools were separately discovered by a fresh STDIO probe. The earlier
full-validation-results.json remains a historical SDK-only result.
macOS, the IDE/app UI and Node.js 22 remain untested. Exact commands for Prachi
are in [PRACHI_MAC_EXECUTION.md](PRACHI_MAC_EXECUTION.md).

REACHABLE and bounded NOT_REACHABLE branches pass controlled tests with synthetic
advisory function metadata. No real affected npm function was proven reachable
in the live inputs; all 20 results were UNKNOWN. Dependency-internal call/taint
analysis, dynamic/framework/callback modeling, workspaces and non-npm lockfiles
remain incomplete. No registry publication check or automated project fix
application is implemented. Token counts/savings were not measured by a model
client. See [LIMITATIONS.md](LIMITATIONS.md) for the complete scope.
