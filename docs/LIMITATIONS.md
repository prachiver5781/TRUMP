# Limits and incomplete advanced features

## Dependency analysis

Only npm `package.json` plus `package-lock.json` versions 1–3 are supported.
Yarn/pnpm/Python/Java/etc. are not supported. Workspaces, `file:`/git dependencies
and local links are flagged when unresolved and are not followed. npm aliases
require resolved package names in the lockfile. Optional platform-specific and
development dependencies are included: the graph describes the lockfile, not a
verified `node_modules` installation or production-only deployment.

Peer edges are included when lock resolution provides them. Inconsistent
manifests/locks and missing mandatory edges produce warnings and partial
vulnerability status. Dependency paths are possible relationships, not proof
that every parent invokes a vulnerability or is compromised.

## Static and reachability analysis

The TypeScript compiler parses source without loading target tsconfig/plugins.
Supported calls include top-level named functions and top-level variable-bound
functions, direct named/namespace imports, basic top-level literal `require`,
local relative module resolution, and known imported member calls. Ordinary
parameter shadowing is resolved through compiler symbols.

Dynamic imports/requires, reflection, computed properties, function aliases,
callbacks, nested methods/functions, class/prototype dispatch, re-exports,
CommonJS export assignment, bundler aliases and framework route/event wiring
are not fully resolved. Missing modules, parse errors, inferred entries and
externally callable exports prevent a closed negative conclusion. Reassigned
bindings and local-function properties are not treated as proven calls.
Top-level side-effect `require('./module')` contributes a module execution edge.
Inline/conditional requires and `call`/`apply`/`bind` use UNKNOWN when not modeled.
Calling another export of a vulnerable package also prevents a negative result
because that export's internal calls are not analyzed.

Entry points come from manifest `main`, `module`, `bin`, and `exports` when they
map to available source. Common `index`/app/server files are fallback candidates
and explicitly marked inferred. Ignored generated build output can make declared
entries unavailable; no source-map or bundler reconstruction is attempted.

Dependency package internals are never read. Application paths into transitive
vulnerable functions therefore usually remain UNKNOWN. Real npm advisories may
not provide supported machine-readable affected-function names. TRACEGUARD
does not infer those names from prose or a familiar package API. Its offline
reachability fixtures deliberately provide synthetic function metadata; live
advisories often produce UNKNOWN even when a familiar API is called.

REACHABLE means a syntactic potential path to an advisory-named function. It does
not evaluate runtime branch conditions, attacker control, input validation,
taint flow or exploit prerequisites. NOT_REACHABLE is restricted to the supported
closed application model and does not prove safety. UNKNOWN is an expected and
honest result, not a low-risk verdict.

## Vulnerability and remediation intelligence

The OSV API is an external dependency. Timeouts, rate limits, malformed responses,
unsupported ranges and missing metadata are handled conservatively. Withdrawn
advisories are excluded. CVEs are returned only when supplied as aliases. Severity
uses supplied database severity or numeric score; uncalculated CVSS vectors are
preserved in details and can result in UNKNOWN severity. No CVSS vector calculator
or unsupported ecosystem range interpreter is claimed.

Verified unaffected versions mean advisory-fixed versions that are outside the
original supported affected ranges and have no matching current OSV records.
Up to eight candidates are queried. There is no npm registry publication check,
release-note compatibility review, unknown-vulnerability guarantee, parent
upgrade inference or automatic fix application. Major-version warnings are
heuristics; patch/minor/0.x changes can still break applications.

Fix comparison matches advisory/alias identity across versions. A disappeared
finding may reflect removal, upgrade, advisory withdrawal or changed intelligence;
it is not proof of a tested secure application. Partial/unavailable scans report
unverified absences. Project-name equality guards obvious comparison mistakes,
but two unrelated projects can share a name; callers must select the right scan.

## Operational scope

Scans and cursors are session-local; a maximum of 20 snapshots are retained.
There is no persistent scan-history database, background watcher, registry cache
purge tool, cross-process locking, or whole-repository atomic snapshot. Cache
TTL bounds ordinary freshness. JSON artifacts/cache files need normal operator
retention management. Forced kills can leave temporary directories.

Hard resource limits can reject unusually large projects instead of delivering a
misleading incomplete clean scan. OSV requests are bounded individually but a
large repository can exceed a host's tool-call timeout. Configure sufficient
timeout and scan smaller independent projects where appropriate. Cancellation
does not forcibly stop every in-flight filesystem operation immediately.

Automated validation runs on Windows using Node.js 24. The project targets Node
22+ and includes macOS configuration. An actual Windows Codex CLI scan and
pagination were subsequently verified (see CODEX_EXECUTION.md); macOS execution
and the IDE/app UI remain untested. Official SDK STDIO clients are also tested.
Exact client-side token counts and token savings are unmeasured.

The full live validation exercised all eleven tools on genuine npm-resolved local
projects and a ZIP. Its 20 real findings all returned UNKNOWN reachability. The
REACHABLE and NOT_REACHABLE algorithm branches are validated with explicitly
synthetic advisory-function metadata, not proven on a real affected npm function.
SBOMs passed the official CycloneDX 1.5 JSON Schema using the SDK's AJV provider;
that provider ignores `iri-reference` and `idn-email` formats for optional fields.
