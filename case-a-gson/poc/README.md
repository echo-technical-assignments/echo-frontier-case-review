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
