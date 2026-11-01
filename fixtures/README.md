# Offline test data

`npm-app` is a synthetic, deliberately vulnerable fixture. Its package names,
advisories, affected functions and fixed versions exist only for deterministic
tests. Never install its dependencies. Production code has no offline advisory
fallback and always queries OSV. `tests/osv.live.ts` separately exercises real
OSV responses for actual lodash versions without executing or installing lodash.
