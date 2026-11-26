# Unbounded `JsonReader` nesting exhausts the heap (gson <= 2.11.0)

| | |
|---|---|
| Package | `com.google.code.gson:gson` (maven) |
| Where | `push()` in `gson/src/main/java/com/google/gson/stream/JsonReader.java` |
| Affected | <= 2.11.0 (tested only at 2.11.0, commit 828a97b; the checkout contains no depth limit) |
| Fixed | 2.12.0 (`1039427ff0100293dd3cf967a53a55282c0fef6b`, PR #2588), fixed silently: no CVE, no GHSA |
| Public ID | none (no CVE, no GHSA), checked 2026-11-04 |
| CWE | CWE-400, Uncontrolled Resource Consumption |
| CVSS 3.1 | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` → **7.5 (High)** |

## Summary

**The library.** Gson is Google's Java library for converting objects to and from JSON. The
direction that matters here is parsing: `JsonReader` is the streaming token parser behind
`Gson.fromJson()` and the public token API integrators drive directly.

**The defect.** The parser promises to read whatever JSON it is handed. To track nesting it keeps
three arrays (`stack`, `pathIndices`, `pathNames`) and doubles them whenever they fill up. In
2.11.0 **there is no maximum nesting depth**: every `[` pushes one more entry, and the parser keeps
doubling its state arrays to match — no depth is ever refused.

The state per level dwarfs the input per level. One `[` is one byte of input, but the measured
parser state is roughly 14 bytes per input byte (calculated, not run): on a 2 GB heap, retained
heap grew from ~16,377 KB to ~28,579 KB to ~53,155 KB as depth went from 1M to 2M to 4M brackets — **linear in
attacker-chosen depth**, released only after `close()`.

On a bounded heap the growth does not stall, it kills. The same parse on a `-Xmx64m` JVM ran to
depth ~2,097,151 and died with `java.lang.OutOfMemoryError` thrown from inside the array-doubling
code, terminating the process (exit code 2). **Allocation failure is the only thing that stops the
parse.**

The contrast that makes it a defect rather than a design choice: 2.12.0 added a nesting limit
(default 255) that refuses over-deep input with a `MalformedJsonException` instead of growing until
the heap dies. 2.11.0 and earlier have no such check.

**The attack.** An attacker submits a small payload of nested `[` characters to a service that
parses attacker-controlled JSON with Gson — a request body handed to `Gson.fromJson()` or a
`JsonReader` token loop. The parser's state grows with the depth the attacker chose, and **the
attacker gets a terminated process** for about 2 MB of input on a 64 MB heap, limited only by the
service's heap size.

| Input | 2.11.0 | 2.12.0 |
|---|---|---|
| control: input capped at 256 brackets | maxStackSize 256, no growth, no `OutOfMemoryError` | — |
| 1M nested arrays (~1 MB) | ~16,377 KB retained heap, 35 ms | refused at depth 255, read, not run |
| 2M nested arrays (~2 MB) | ~28,579 KB retained heap, 52 ms | refused at depth 255, read, not run |
| 4M nested arrays (~4 MB) | ~53,155 KB retained heap, 93 ms | refused at depth 255, read, not run |
| unbounded, on a `-Xmx64m` heap | **OutOfMemoryError at depth ~2,097,151, exit code 2** | refused at depth 255, read, not run |

Captured output: `logs/baseline.stdout.log` (streamed input, 2 GB heap, then the 64 MB child JVM)
and `logs/control.stdout.log`.

### Why this vector

| Metric | Value | Why |
|---|---|---|
| Attack Vector | Network | the JSON reaches a service over its request interface |
| Attack Complexity | Low | any payload of nested `[` characters works, `logs/baseline.stdout.log` |
| Privileges Required | None | an unauthenticated request body is enough |
| User Interaction | None | no victim action is needed beyond the service parsing the body |
| Scope | Unchanged | the crash is confined to the parsing process |
| Confidentiality | None | nothing was measured that discloses data |
| Integrity | None | nothing was measured that alters data |
| Availability | High | the parse terminated the JVM with exit code 2, `logs/baseline.stdout.log` |

## Am I affected?

**Yes**, if you parse attacker-controlled JSON with `com.google.code.gson:gson` <= 2.11.0 on a
process with a bounded heap and nothing limits nesting depth before Gson sees the body.

**No**, if:
- you are on 2.12.0 or newer, where `JsonReader` refuses nesting deeper than its limit
  (default 255) with a `MalformedJsonException`;
- your JSON is not attacker-controlled;
- something upstream of Gson rejects payloads over-deep or oversized before parsing.

A request body size cap alone doesn't help: the payload that exhausted a 64 MB heap is
about 2 MB (calculated, not run).

## What this does not claim

- **Impact:** denial of service only; no data disclosure, corruption or code execution was measured.
- **Tested on:** gson 2.11.0 built from commit `828a97b`, JDK 11, Linux aarch64, with 2 GB and
  64 MB heaps.
- **Versions run:** only 2.11.0 was run; the 2.12.0 nesting-limit behaviour is read from the
  upstream source, not run.
- **Not run end to end:** the consumer is a minimal public-API test program, not a deployed service.
  No `Gson.fromJson()` call with a complete document (the PoC drives the token API directly), and
  no concurrent requests.
- **The fix:** the 2.12.0 default limit of 255 and `setNestingLimit()` are read, not run.

## Verification

### Is this already known?

We found no CVE and no GHSA for a Gson nesting-depth resource exhaustion as of 2026-11-04. The
upstream fix (PR #2588, in 2.12.0) discusses `StackOverflowError` in recursive adapters, not heap
exhaustion, and no advisory accompanies it. The repository's published security advisories list is
empty.

### Is it still unfixed?

Fixed upstream. `push()` in `JsonReader.java` at the `main` branch head as of 2026-11-04 refuses
nesting deeper than the limit (default 255) with a `MalformedJsonException`; the fix first shipped
in 2.12.0 (2025-01-27) and is in every release since. Releases <= 2.11.0 remain affected.

### What does upstream think?

The project has no `SECURITY.md` of its own; the Google organisation's
([google/.github](https://github.com/google/.github/blob/master/SECURITY.md)) routes vulnerability
reports to https://g.co/vulnz. Nothing upstream calls the nesting limit a security fix: the PR
describes it as `StackOverflowError` protection for recursive `TypeAdapter` implementations and a
knob for unusually deep data.

## Running the PoC

`poc/Repro.java` uses only the public API (`JsonReader`, `JsonToken`); its `BracketReader` streams
`[` characters on demand with O(1) memory, so measured heap growth is parser state, not input.

- **Baseline** parses depths 1M/2M/4M on a `-Xmx2g` heap, then spawns a `-Xmx64m` child JVM that
  loops `beginArray()` until `OutOfMemoryError`. `run.sh baseline` exits 0 only when the OOM with a
  `JsonReader.push` frame reproduced.
- **Control** runs the same streamed-input traversal with the `Reader` capped at 256 brackets (the
  upstream depth limit the finding says is missing): `maxStackSize` stays at 256, no OOM.

```sh
git clone https://github.com/google/gson repo
git -C repo checkout 828a97be0f8d58108b140b77df8dc76b657f4a87
OFFLINE= sh poc/run.sh baseline   # builds gson (JDK 11, Maven), runs the shape points and the -Xmx64m child
OFFLINE= sh poc/run.sh control    # same traversal, input capped at 256 brackets
```

Or use the `Dockerfile`, which does the same. The exact commands and exit codes of the captured
runs are in `logs/commands.jsonl`.
