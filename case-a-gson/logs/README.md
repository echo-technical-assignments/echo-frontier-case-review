# Logs

- `baseline.stdout.log` — produced by `sh poc/run.sh baseline` (exit 0). Full stdout of
  the baseline run. Key lines (also extracted in `baseline.summary.log`):
  - built artifact `out/src/gson/target/gson-2.11.0.jar`,
    SHA-256 `8cabe31a1a6448b346f0dd2c536fee9578be117a9c2c995902bd43d931439385`
  - depth=1,000,000 → maxStackSize=1,000,000, timeMs=35, heapUsedKB(approx)=16,377
  - depth=2,000,000 → maxStackSize=2,000,000, timeMs=52, heapUsedKB(approx)=28,579
  - depth=4,000,000 → maxStackSize=4,000,000, timeMs=93, heapUsedKB(approx)=53,155
  - oom-phase: `java.lang.OutOfMemoryError: Java heap space` with stack
    `Arrays.copyOf` ← `com.google.gson.stream.JsonReader.push` (JsonReader.java:1415)
    ← `com.google.gson.stream.JsonReader.beginArray` (JsonReader.java:426), at depth
    ~2,097,151 on the `-Xmx64m` child JVM, which exited with code 2
  - `oom-phase: heap exhaustion outcome REPRODUCED`
- `baseline.stderr.log` — stderr of the baseline run (empty; build ran with `-q`).
- `baseline.summary.log` — extracted summary of the baseline stdout (same command),
  for reviewers who want only the essential lines.
- `control.stdout.log` — produced by `sh poc/run.sh control` (exit 0). States in words
  that the sink was not reached ("JsonReader.push() stack-doubling growth absent; no
  unbounded heap growth", "no OutOfMemoryError") with the deep-nesting condition
  removed (input capped at 256 brackets; max stackSize 256).
- `control.stderr.log` — stderr of the control run (empty).
- `commands.jsonl` — the two commands and their exit codes.

Built artifact: `gson-2.11.0.jar` from the gson module of the checkout at commit
`828a97be0f8d58108b140b77df8dc76b657f4a87`, SHA-256
`8cabe31a1a6448b346f0dd2c536fee9578be117a9c2c995902bd43d931439385`.
