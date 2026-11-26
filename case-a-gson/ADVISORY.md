# Unbounded JSON nesting in `JsonReader` exhausts heap in `push()` (no depth limit; fixed silently in 2.12.0)

Draft report to Google's vulnerability intake (https://g.co/vulnz).

| Field | Value |
|---|---|
| Package | `com.google.code.gson:gson` (maven) |
| Affected | <= 2.11.0 |
| Patched | 2.12.0 |
| Severity | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (7.5 High) |
| CWEs | CWE-400 |

### Summary

Your fix in `1039427ff0100293dd3cf967a53a55282c0fef6b` ("Add nesting limit for `JsonReader`", PR
#2588, first released in 2.12.0 on 2025-01-27) also closes a heap-exhaustion denial of service in
releases <= 2.11.0. There is no CVE and no published GHSA for it as of 2026-11-04, so every
scanner reads `com.google.code.gson:gson:2.11.0` and earlier as safe. We ran a PoC against 2.11.0
built from the release commit; the fixed behaviour is read from your `main` branch, not run.

In 2.11.0, a payload of ~2 MB of `[` characters drove `beginArray()` to depth ~2,097,151 on a
`-Xmx64m` JVM and killed it with `java.lang.OutOfMemoryError` from `JsonReader.push()` (exit code
2); the parser refused no depth.

Each `beginArray()` calls `push()`, which only checks `stackSize == stack.length` before doubling
`stack`, `pathIndices` and `pathNames` (`JsonReader.java:1411-1419`). The input costs one byte per
level; the parser state costs roughly 14 bytes per level (calculated, not run), so the heap dies
long before the input gets large.

### Impact

Any service that parses attacker-supplied JSON with Gson on a bounded heap — a request body
handed to `Gson.fromJson()` or a `JsonReader` loop — can be terminated by a payload of nested
brackets a fraction of the heap in size. The attacker chooses the depth; ~2 MB of input exhausted
a 64 MB heap in our run.

### CVE request

There is no CVE and no published GHSA for this fix as of 2026-11-04, so releases <= 2.11.0 are
invisible to advisory-driven scanners. Nothing in commit `1039427ff0100293dd3cf967a53a55282c0fef6b`,
PR #2588 or the 2.12.0 release notes calls it a security fix, so we are asking rather than
assuming: please publish an advisory for the nesting limit, covering the CWE-400 heap exhaustion it
closes, with affected `<= 2.11.0` and patched `2.12.0`. Google can assign the CVE,
crediting the fix to Marcono1234's PR #2588.

### Fix status

- **Their fix:** `1039427ff0100293dd3cf967a53a55282c0fef6b` in 2.12.0 refuses nesting deeper than
  the limit (default 255) with a `MalformedJsonException`, before any array doubling. Read, not
  run, at the `main` branch head as of 2026-11-04.
- **Residual:** applications that raise the limit with `setNestingLimit()` or disable it restore
  the exposure; the default is protective. `JsonTreeReader` ignores the limit by design (read, not
  run), but it parses an in-memory tree the application already built.
- **Unfixed twin:** none found; `beginObject()` goes through the same `push()` and is covered by
  the same check.
