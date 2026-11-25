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

### How it breaks

**In one line:** the parser's nesting state grows without bound with the depth of the input, and
nothing refuses a depth until the heap is exhausted.

```
Input:  N bytes of '[' (a ~2 MB payload exhausted a 64 MB heap)

JsonReader, while parsing:
  beginArray() consumes one '['
          │
          ├─ push() records one more nesting level
          │     → stackSize grows by 1 per '['
          │
          └─ stackSize == stack.length?
                → Arrays.copyOf doubles stack, pathIndices, pathNames
                → heap grows linearly with depth      ← nothing limits this
                → on a bounded heap: OutOfMemoryError, process exits
```

**Cost:** retained parser state grows linearly with nesting depth; time stays in the
tens of milliseconds.

| Input | 2.11.0 | 2.12.0 |
|---|---|---|
| 1M nested arrays (~1 MB) | ~16,377 KB retained heap, 35 ms | refused at depth 255, read, not run |
| 2M nested arrays (~2 MB) | ~28,579 KB retained heap, 52 ms | refused at depth 255, read, not run |
| 4M nested arrays (~4 MB) | ~53,155 KB retained heap, 93 ms | refused at depth 255, read, not run |
| unbounded, on a `-Xmx64m` heap | **OutOfMemoryError at depth ~2,097,151, exit code 2** | refused at depth 255, read, not run |

Timings: `logs/baseline.stdout.log` (streamed input, 2 GB heap, then the 64 MB child JVM).

### Terms

| Term | What it means here |
|---|---|
| `JsonReader` | Gson's streaming pull parser; the token API behind `Gson.fromJson()` |
| nesting state | the parser's `stack`, `pathIndices` and `pathNames` arrays; one entry per open array or object |
| depth | number of simultaneously open arrays; here, the number of `[` characters |
| streamed input | the PoC's `Reader` emits `[` on demand holding O(1) memory, so measured heap growth is parser state, not input buffering |

### What it looks like

**The setup.** A service parses attacker-supplied request bodies with Gson. This is a common
pattern; no real service was tested.

```java
JsonReader reader = new JsonReader(new InputStreamReader(requestBody));
reader.beginArray(); // a token loop, or Gson.fromJson(...), which uses the same reader
```

**What we ran.** A loop of `beginArray()` over a payload of `[` characters streamed from an
O(1)-memory `Reader`, on gson built from `gson-parent-2.11.0 @ 828a97b` (jar SHA-256
`8cabe31a1a6448b346f0dd2c536fee9578be117a9c2c995902bd43d931439385`). Condensed from
`poc/Repro.java`, with the same calls and arguments:

```java
JsonReader r = new JsonReader(new BracketReader(depth)); // streams '[' on demand
for (int i = 0; i < depth; i++) { r.beginArray(); }      // then read stackSize and heap
```

| Input | 2.11.0 | 2.12.0 |
|---|---|---|
| 4M nested arrays (streamed) | maxStackSize 4,000,000, ~53,155 KB retained, 93 ms | not run |
| unbounded nested arrays, `-Xmx64m` child JVM | **OutOfMemoryError inside `push()`, exit code 2** | not run |
| control: input capped at 256 brackets | maxStackSize 256, no growth, no `OutOfMemoryError` | — |

Captured lines (`logs/baseline.stdout.log`):

```
depth=1,000,000  maxStackSize=1,000,000  timeMs=35  heapUsedKB(approx)=16,377
depth=2,000,000  maxStackSize=2,000,000  timeMs=52  heapUsedKB(approx)=28,579
depth=4,000,000  maxStackSize=4,000,000  timeMs=93  heapUsedKB(approx)=53,155
oom-phase: java.lang.OutOfMemoryError: Java heap space at depth ~2097151
	at com.google.gson.stream.JsonReader.push(JsonReader.java:1415)
	at com.google.gson.stream.JsonReader.beginArray(JsonReader.java:426)
oom-phase: child JVM exit code 2
```

Captured lines (`logs/control.stdout.log`):

```
control: deep-nesting condition removed (input capped at depth 256)
control: max stackSize 256 (capped input; stream ends at 256 brackets)
control: JsonReader.push() stack-doubling growth absent; no unbounded heap growth
control: no OutOfMemoryError
```

The retained heap tracks the depth the attacker chooses, and the state is released only after
`close()`. Reproduce with `poc/run.sh`.

**Not shown:** no real HTTP service was run, no `Gson.fromJson()` call with a complete document
(the PoC drives the token API directly), and no concurrent requests.

### Am I affected?

**Yes**, if you parse attacker-controlled JSON with `com.google.code.gson:gson` <= 2.11.0 on a
process with a bounded heap and nothing limits nesting depth before Gson sees the body.

**No**, if:
- you are on 2.12.0 or newer, where `JsonReader` refuses nesting deeper than its limit
  (default 255) with a `MalformedJsonException`;
- your JSON is not attacker-controlled;
- something upstream of Gson rejects payloads over-deep or oversized before parsing.

A request body size cap alone doesn't help: the payload that exhausted a 64 MB heap is
about 2 MB (calculated, not run).

### What this does not claim

- **Impact:** denial of service only; no data disclosure, corruption or code execution was measured.
- **Tested on:** gson 2.11.0 built from commit `828a97b`, JDK 11, Linux aarch64, with 2 GB and
  64 MB heaps.
- **Versions run:** only 2.11.0 was run; the 2.12.0 nesting-limit behaviour is read from the
  upstream source, not run.
- **Not run end to end:** the consumer is a minimal public-API test program, not a deployed service.
- **The fix:** the 2.12.0 default limit of 255 and `setNestingLimit()` are read, not run.

## The patch commit

**What it changes.** `1039427ff0100293dd3cf967a53a55282c0fef6b` — "Add nesting limit for
`JsonReader`" (PR [#2588](https://github.com/google/gson/pull/2588), merged 2024-07-19 by
Marcono1234) — makes `push()` refuse nesting deeper than a configurable limit, default 255, with a
`MalformedJsonException`. First released in 2.12.0 (2025-01-27).

```diff
 private void push(int newTop) throws MalformedJsonException {
+    // - 1 because stack contains as first element either EMPTY_DOCUMENT or NONEMPTY_DOCUMENT
+    if (stackSize - 1 >= nestingLimit) {
+      throw new MalformedJsonException(
+          "Nesting limit " + nestingLimit + " reached" + locationString());
+    }
+
     if (stackSize == stack.length) {
       int newLength = stackSize * 2;
```

**Why it's silent:** nothing in the commit, the PR or the 2.12.0 release notes calls it a security
fix. The PR frames the limit as protection against `StackOverflowError` in recursive
`TypeAdapter` implementations and as an escape hatch for users with deeply nested data, and the
release notes list it plainly among the release's other changes: "Add nesting limit for
`JsonReader`". No CVE
and no GHSA cover it.

- **Without the upgrade:** on <= 2.11.0 there is no depth setting to raise or lower — no library
  setting helps; a limit has to be enforced before Gson sees the body.

## At a glance

| | |
|---|---|
| Package | `com.google.code.gson:gson` (maven) |
| Where | `push()` in `gson/src/main/java/com/google/gson/stream/JsonReader.java` |
| Affected | <= 2.11.0 (tested only at 2.11.0, commit 828a97b; the checkout contains no depth limit) |
| Fixed | 2.12.0 (`1039427ff0100293dd3cf967a53a55282c0fef6b`, PR #2588) |
| Public ID | none (no CVE, no GHSA), checked 2026-11-04 |
| CWE | CWE-400, Uncontrolled Resource Consumption |
| CVSS 3.1 | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` → **7.5 (High)** |

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
