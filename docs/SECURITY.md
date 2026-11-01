# Security model

## Authorization boundary

`TRACEGUARD_ALLOWED_ROOTS` is a mandatory, trusted process-environment JSON
allowlist (or the trusted server installation's `.env`, with process values taking
precedence). It cannot be changed through a tool argument. Paths must be absolute,
exist, resolve inside an allowed root, and have the expected file/directory type.
String-prefix lookalikes and symlink escapes are rejected. Initial repository,
ZIP and verification calls require `authorized: true`; the host must set this
only after explicit user authorization. A boolean is a consent signal, not an
identity system. Do not give an untrusted model a broad filesystem allowlist.

The server-local `.env` is bounded to 64 KiB, must be a regular non-symlink file,
and supplies only TRACEGUARD configuration keys. It cannot set NODE_OPTIONS or
PATH. The current working directory and scanned repositories are never searched
for environment files. Configured roots are canonicalized and must exist, be
readable directories and not resolve to a whole filesystem/drive root.

Source discovery skips symlinks and ignored build/dependency/VCS directories.
Each read checks regular-file status, realpath containment, size and stable
file metadata, uses no-follow opening when supported, and bounds bytes read.
No tool accepts an arbitrary output path or arbitrary snippet path.

## ZIP protections

- Compressed archive limit: 100 MiB.
- Entry count: 10,000, including directories; maximum nesting: 64 components.
- Per-entry expanded limit: 16 MiB; declared and streamed total: 200 MiB.
- Reject `..`, absolute/drive/UNC/backslash/alternate-stream paths, NULs,
  empty components, Windows device names, trailing periods/spaces and collisions.
- Reject UNIX symlinks/special files and encrypted entries.
- Extract sequentially to a new private temporary directory using exclusive
  file creation. Enforce streamed byte counts rather than trusting ZIP metadata.
- Remove only verified server-owned `extract-*` directories in `finally`.

The `yauzl` parser validates entry sizes and decompression. CRC integrity is not
an authenticity/signature verification feature. ZIPs may contain other files,
but none are executed. A hard crash or forced process kill can leave a temporary
directory; remove stale server-owned temporary data with the server stopped.

## Resource limits

Repository traversal observes at most 10,000 entries and 64 directory levels;
ignored subtrees are not traversed. Source files are at most 2 MiB each, with
200 MiB total selected source bytes. Manifest/lockfile files are at most 16 MiB.
Graphs are capped at 20,000 lock entries. Per-file AST limits bound visits,
calls, declarations and imports; total call graph facts are capped at 200,000.
Hitting a hard local limit fails the scan explicitly rather than reporting a
clean result. Dependency paths and OSV pagination also disclose bounded analysis.

OSV requests have timeouts, bounded retries, response limits and bounded
hydration concurrency. Responses are schema-validated. Failed/incomplete
intelligence produces partial/unavailable status and never fabricated records.

## Execution and privacy

The server has no shell, subprocess, package-install or arbitrary-command tool.
It does not load scanned-project modules, npm configuration, `.env`, lifecycle scripts,
git hooks, TypeScript plugins or build tools. It parses source with a compiler
API; it does not compile/execute the application. Suggested commands require
separate user approval outside TRACEGUARD.

Only npm package names and exact versions (including private dependency names)
are sent to `https://api.osv.dev`. Repository source, lockfile contents, secrets,
paths and snippets are not sent to OSV or an external model by the server.
Returned findings/advisory text and paths are untrusted data, never instructions.

No full source files are returned by tools. Opt-in snippets mask literal text
and comments and are limited to evidence lines. Redaction is defensive, not a
general secret detector; unusual source syntax/identifiers can still be sensitive.
Do not request snippets from sensitive files without reviewing this constraint.

The runtime writes no project files. Server-owned artifacts contain SBOM/finding
data; static caches contain paths/imports/symbols, not source text. Data-directory
paths must be trusted and not shared with untrusted writers. Directories/files
use 0700/0600 where the OS supports POSIX modes; Windows access follows ACLs.
Cache filenames are hashes and artifact names are UUIDs. Cache expiry, schema
versioning and input hashes prevent ordinary stale-result reuse; this is not a
cryptographically authenticated cache against a malicious local user.

## Remaining threat boundaries

The scanner is not an OS sandbox. Another process with write access can race
filesystem checks; realpath/no-follow checks reduce exposure but do not promise
atomic snapshot semantics across platforms. Do not scan actively adversarial
mutable trees under a more privileged account. No malware detection, registry
signature verification, package integrity retrieval, or runtime exploit proof is
claimed. An integrity string in a lockfile is preserved as metadata, not verified
against a downloaded package.

stdout is reserved for MCP. Startup failures emit only sanitized code/message to
stderr. Application errors hide filesystem stack traces, environment contents
and raw network errors. Logs never print source or `.env` contents.

