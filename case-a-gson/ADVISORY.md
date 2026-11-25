## How to send

- **To:** https://g.co/vulnz (Google's vulnerability intake and triage form)
- **Why this channel:** https://github.com/google/.github/blob/master/SECURITY.md says
  "Please use https://g.co/vulnz to report security vulnerabilities." The gson repository has no
  `SECURITY.md` of its own (checked 2026-11-04), so the organisation's policy applies.
- **Routing rule:** "The Google Security Team will process your report within a day, and respond
  within a week (although it will depend on the severity of your report)." — no severity or type
  routing; all reports go through the same form.
- **Packaging:** paste the advisory below the line into the form's Description; no attachments needed; no encryption key published.
- **CVE:** ask in prose. Google can assign CVEs; nothing in the policy forbids asking, and no project
  rule restricts who may request one.

| Field | Value |
|---|---|
| Title | Unbounded JSON nesting in `JsonReader` exhausts heap in `JsonReader.push()` (no depth limit; fixed silently in 2.12.0) |
| Ecosystem | maven |
| Package | `com.google.code.gson:gson` |
| Affected | <= 2.11.0 |
| Patched | 2.12.0 |
| Severity | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (7.5 High) |
| CWEs | CWE-400 |

---

# Unbounded JSON nesting in `JsonReader` exhausts heap in `push()` (no depth limit; fixed silently in 2.12.0)

### Summary

Your fix in `1039427ff0100293dd3cf967a53a55282c0fef6b` ("Add nesting limit for `JsonReader`", PR
#2588, first released in 2.12.0 on 2025-01-27) also closes a heap-exhaustion denial of service in
releases <= 2.11.0. There is no CVE and no published GHSA for it as of 2026-11-04, so every
scanner reads `com.google.code.gson:gson:2.11.0` and earlier as safe. We ran a PoC against 2.11.0
built from the release commit; the fixed behaviour is read from your `main` branch, not run.

In 2.11.0, a payload of ~2 MB of `[` characters drove `beginArray()` to depth ~2,097,151 on a
`-Xmx64m` JVM and killed it with `java.lang.OutOfMemoryError` from `JsonReader.push()` (exit code
2); the parser refused no depth.

| Input to `beginArray()` | Size | 2.11.0 |
|---|---|---|
| control: 256 nested arrays | 256 bytes | parses to end of input, no growth beyond the initial array, no OOM |
| unbounded nested arrays, `-Xmx64m` | ~2 MB when it dies | **OutOfMemoryError at depth ~2,097,151, exit code 2** |

Line numbers and results refer to **`gson-parent-2.11.0`** (`828a97b`).

### Details

An attacker sends JSON that is nothing but opening brackets. Each `beginArray()` consumes one `[`
and calls `push()`, which appends one entry to each of the three nesting-state arrays, and
whenever they fill, `Arrays.copyOf` doubles them. The input costs one byte per level; the parser
state costs roughly 14 bytes per level (calculated, not run), so the heap dies long before the
input gets large. Nothing in 2.11.0 refuses a depth — allocation failure is the only stop.

1. `gson/src/main/java/com/google/gson/stream/JsonReader.java:426` `beginArray()` consumes each
   `[` and calls `push(JsonScope.EMPTY_ARRAY)`.
2. `gson/src/main/java/com/google/gson/stream/JsonReader.java:1411-1419` `push()` checks only
   `stackSize == stack.length` before doubling.
3. `gson/src/main/java/com/google/gson/stream/JsonReader.java:1411-1419` the doubling
   `Arrays.copyOf` grows `stack`, `pathIndices` and `pathNames` to `stackSize * 2`. **There is no
   depth check in 2.11.0.**
4. `gson/src/main/java/com/google/gson/stream/JsonReader.java:1411-1419` on a bounded heap the
   copy fails: `java.lang.OutOfMemoryError: Java heap space` at
   `JsonReader.push(JsonReader.java:1415)` reached from `JsonReader.beginArray
   (JsonReader.java:426)`.

**Missing:** the nesting-limit check your `main` branch now performs at the top of `push()`
(`stackSize - 1 >= nestingLimit` → `MalformedJsonException`, default limit 255).

#### Reachability

- **Entry points:** `JsonReader.beginArray()` / `beginObject()` / `peek()` / `skipValue()`
  directly, and `Gson.fromJson()` via the built-in adapters, which use the same reader.
- **Needs:** the application parses attacker-controlled JSON with no upstream nesting-depth or
  payload check; the exhaustion depth depends on the heap (~2.1M at `-Xmx64m` in our run).
- **Not enough:** a well-formed document is not needed — bare `[` characters suffice; whitespace
  or a request body size cap alone doesn't help, since ~2 MB exhausts a 64 MB heap.
- **Doesn't help:** there is no 2.11.0 setting that bounds depth; `close()` releases the state
  only after the fact.
- **Not claimed:** we ran only the 2.11.0 build; no deployed service was attacked, and no data
  disclosure or corruption is involved.
- **Not examined:** forks and other consumers' own depth handling.

### PoC

**Needs:** JDK 11, Maven, network for the first build. Runs a child JVM bounded to `-Xmx64m`
that dies by `OutOfMemoryError` — expect that JVM to exit non-zero; that is the finding.

<details>
<summary><code>poc/README.md</code></summary>

````text
# PoC: Unbounded JsonReader nesting-state growth (gson 2.11.0 @ 828a97b)

## What it proves

`JsonReader.push()` (`gson/src/main/java/com/google/gson/stream/JsonReader.java:1411-1418`)
doubles the parser's three nesting-state arrays (`stack`, `pathIndices`, `pathNames`)
via `Arrays.copyOf` whenever `stackSize` reaches `stack.length`, with **no maximum
nesting depth** in this version. Parsing attacker-supplied JSON consisting of deeply
nested `[` delimiters through the public `JsonReader.beginArray()` API (the normal
token loop an integrator uses) drives `stackSize` as deep as the attacker chooses, and
the parser never refuses any depth — until the heap is exhausted and the process dies
with `OutOfMemoryError`.

Two effects are demonstrated on the same build:

1. **Cost shape.** Retained parser-state heap grows linearly with attacker-chosen
   nesting depth; after `close()` the state is released. The input is streamed from an
   O(1)-memory `Reader` (one `[` per `read()` call, no backing string), so every
   measured byte of heap growth is JsonReader nesting state, not input buffering:

   | depth (brackets) | maxStackSize | time  | heap used (approx) |
   |-----------------|--------------|-------|--------------------|
   | 1,000,000       | 1,000,000    | 35 ms | ~16 MB             |
   | 2,000,000       | 2,000,000    | 52 ms | ~29 MB             |
   | 4,000,000       | 4,000,000    | 93 ms | ~53 MB             |

   Doubling the input roughly doubles the retained state: **linear** in depth.

2. **Heap exhaustion.** The same parse driven on a bounded heap (`-Xmx64m` child JVM,
   same streamed input) runs `beginArray()` until `JsonReader.push()` cannot allocate:

   ```
   java.lang.OutOfMemoryError: Java heap space
       at java.base/java.util.Arrays.copyOf(Arrays.java:3793)
       at com.google.gson.stream.JsonReader.push(JsonReader.java:1415)
       at com.google.gson.stream.JsonReader.beginArray(JsonReader.java:426)
   ```

   The OOM occurred at depth ~2,097,151 (~2 MB of `[` characters) and terminated the
   child JVM (exit code 2). The parser refused no depth; the allocation failure inside
   `push()` is the only thing that stopped it. The parent process scans the child's
   combined output for the OOM and the `JsonReader.push` frame and fails (exit 1) if
   either is absent, so `run.sh baseline` exits 0 only when heap exhaustion
   reproduced.

## Base

- Repository: https://github.com/google/gson
- Commit: 828a97be0f8d58108b140b77df8dc76b657f4a87 (`gson-parent-2.11.0`)
- Module built: `gson/` (Maven, JDK 11), artifact `gson-2.11.0.jar`
  SHA-256 `8cabe31a1a6448b346f0dd2c536fee9578be117a9c2c995902bd43d931439385`

## Consumer

`Repro.java` uses only the public API (`com.google.gson.stream.JsonReader`,
`JsonToken`). `BracketReader` (inside `Repro.java`) streams `[` characters on demand
and holds O(1) memory. Baseline: (a) parses depths 1M/2M/4M on a `-Xmx2g` heap and
reports `maxStackSize`, time, and retained heap via the reflective `stackSize` field;
(b) spawns a child JVM with `-Xmx64m` that loops `beginArray()` until
`OutOfMemoryError`, and reports whether the OOM stack shows `JsonReader.push`.
Control: the same streamed-input traversal, but the `Reader` is capped at 256
brackets (the upstream depth limit the finding says is missing); the traversal runs
to end of input and reports that `push()` growth was absent and no OOM occurred.

## Runs

- `OFFLINE= sh poc/run.sh baseline` — exit 0. Sink reached: `maxStackSize` reached
  4,000,000 in the shape phase; in the bounded-heap phase the parse ran to depth
  ~2,097,151 and died with `OutOfMemoryError` inside `JsonReader.push()` (stack:
  `Arrays.copyOf` ← `JsonReader.push` ← `JsonReader.beginArray`). See
  `logs/baseline.stdout.log` and `logs/baseline.summary.log`.
- `OFFLINE= sh poc/run.sh control` — exit 0. Sink not reached: with the input capped
  at 256 brackets, `maxStackSize` stays at 256, the doubling growth beyond the initial
  array does not run, and there is no `OutOfMemoryError`. See
  `logs/control.stdout.log`.

## Reviewer steps

```sh
git clone https://github.com/google/gson repo
git -C repo checkout 828a97be0f8d58108b140b77df8dc76b657f4a87
OFFLINE= sh poc/run.sh baseline
OFFLINE= sh poc/run.sh control
```
````

</details>


```bash
git clone https://github.com/google/gson repo
git -C repo checkout 828a97be0f8d58108b140b77df8dc76b657f4a87
OFFLINE= sh poc/run.sh baseline   # builds gson, runs the shape points and the -Xmx64m child
OFFLINE= sh poc/run.sh control    # same traversal, input capped at 256 brackets
```

**Results** (2026-11-04, Linux aarch64, JDK 11, gson jar SHA-256
`8cabe31a1a6448b346f0dd2c536fee9578be117a9c2c995902bd43d931439385`; times from
`System.nanoTime()` around the parse loop):

| Input | Size | 2.11.0 | 2.12.0 |
|---|---|---|---|
| control: 256 nested arrays | 256 bytes | maxStackSize 256, no OOM | not run |
| 1M nested arrays (streamed) | ~1 MB | maxStackSize 1,000,000, ~16,377 KB retained, 35 ms | not run |
| 2M nested arrays (streamed) | ~2 MB | maxStackSize 2,000,000, ~28,579 KB retained, 52 ms | not run |
| 4M nested arrays (streamed) | ~4 MB | maxStackSize 4,000,000, ~53,155 KB retained, 93 ms | not run |
| unbounded, `-Xmx64m` child | ~2 MB | **OutOfMemoryError at depth ~2,097,151, exit code 2** | refused at depth 255, read, not run |

Retained heap is measured with the parser state alive, after `System.gc()`, on a stream whose
`Reader` holds O(1) memory — every measured byte is parser state. On your `main` branch,
`push()` throws `MalformedJsonException` before any of this growth (read, not run).

<details>
<summary><code>logs/baseline.summary.log</code></summary>

```text
built /tmp/tmpjy4p2tu9/poc/../out/src/gson/target/gson-2.11.0.jar sha256 8cabe31a1a6448b346f0dd2c536fee9578be117a9c2c995902bd43d931439385
mode: baseline
artifact: gson jar built from repo @ 828a97b (gson-parent-2.11.0)
depth=1,000,000  maxStackSize=1,000,000  timeMs=35  heapUsedKB(approx)=16,377
depth=2,000,000  maxStackSize=2,000,000  timeMs=52  heapUsedKB(approx)=28,579
depth=4,000,000  maxStackSize=4,000,000  timeMs=93  heapUsedKB(approx)=53,155
oom-phase: java.lang.OutOfMemoryError: Java heap space at depth ~2097151
	at java.base/java.util.Arrays.copyOf(Arrays.java:3793)
	at com.google.gson.stream.JsonReader.push(JsonReader.java:1415)
	at com.google.gson.stream.JsonReader.beginArray(JsonReader.java:426)
	at repro.Repro.oomPhase(Repro.java:94)
oom-phase: heap exhaustion outcome REPRODUCED
effect: heap exhaustion reproduced: deep JSON nests until JsonReader.push()
        cannot allocate, terminating the process with OutOfMemoryError.
```

</details>


### Impact

Any service that parses attacker-supplied JSON with Gson on a bounded heap — a request body
handed to `Gson.fromJson()` or a `JsonReader` loop — can be terminated by a payload of nested
brackets a fraction of the heap in size. The attacker chooses the depth; ~2 MB of input exhausted
a 64 MB heap in our run.

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` → **7.5 (High)**

| Metric | Value | Why |
|---|---|---|
| AV | Network | the JSON arrives over the service's request interface |
| AC | Low | bare `[` characters suffice, no timing or special state |
| PR | None | an unauthenticated request body is enough |
| UI | None | no victim interaction beyond the service parsing the body |
| S | Unchanged | the crash is confined to the parsing process |
| C | None | no data disclosure measured |
| I | None | no data alteration measured |
| A | High | the parse terminated the JVM, `logs/baseline.stdout.log` |

### CVE request

There is no CVE and no published GHSA for this fix as of 2026-11-04, so releases <= 2.11.0 are
invisible to advisory-driven scanners. Nothing in commit `1039427ff0100293dd3cf967a53a55282c0fef6b`,
PR #2588 or the 2.12.0 release notes calls it a security fix, so we are asking rather than
assuming: please publish an advisory for the nesting limit, covering the CWE-400 heap exhaustion it
closes, with affected `<= 2.11.0` and patched `2.12.0`. Google can assign the CVE,
crediting the fix to Marcono1234's
PR #2588. A before-and-after PoC is above.

### Fix status

- **Their fix:** `1039427ff0100293dd3cf967a53a55282c0fef6b` in 2.12.0 refuses nesting deeper than
  the limit (default 255) with a `MalformedJsonException`, before any array doubling. Read, not
  run, at the `main` branch head as of 2026-11-04.
- **Residual:** applications that raise the limit with `setNestingLimit()` or disable it restore
  the exposure; the default is protective. `JsonTreeReader` ignores the limit by design (read, not
  run), but it parses an in-memory tree the application already built.
- **Unfixed twin:** none found; `beginObject()` goes through the same `push()` and is covered by
  the same check.
