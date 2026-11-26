#!/bin/sh
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="${SRC_DIR:-$HERE/../repo}"
OUT="${OUT:-$HERE/../out}"
OFFLINE="${OFFLINE-}"
mkdir -p "$OUT"

MODE="${1:-baseline}"

export JAVA_HOME=/opt/temurin-11-jdk
JAR="$OUT/src/gson/target/gson-2.11.0.jar"
CP="$JAR"

if [ "$MODE" = "control" ]; then
  # Reuse the already-built artifact and classes; no rebuild. Same streamed-input
  # driver, but the deep-nesting condition is capped before parsing.
  echo "built artifact (reused): $JAR"
  if [ -f "$JAR" ]; then
    echo "sha256 $(sha256sum "$JAR" | cut -d' ' -f1)"
  fi
  "$JAVA_HOME/bin/java" -cp "$OUT/classes:$CP" repro.Repro control
  exit 0
fi

rm -rf "$OUT/src" && mkdir -p "$OUT/src"
git -C "$SRC_DIR" archive HEAD | tar -x -C "$OUT/src"
(cd "$OUT/src/gson" && mvn ${OFFLINE:+-o} -q package -DskipTests -Dmaven.javadoc.skip=true -Dmaven.source.skip=true)

JAR="$(ls "$OUT"/src/gson/target/gson-*.jar | head -1)"
echo "built $JAR sha256 $(sha256sum "$JAR" | cut -d' ' -f1)"

rm -rf "$OUT/classes" && mkdir -p "$OUT/classes"
(cd "$HERE" && "$JAVA_HOME/bin/javac" -d "$OUT/classes" -cp "$JAR" Repro.java)

# Shape run on a 2 GB heap, then a child JVM bounded to -Xmx64m whose deep-nesting
# parse runs until JsonReader.push()'s state-array doubling exhausts the heap.
"$JAVA_HOME/bin/java" -Xmx2g -cp "$OUT/classes:$JAR" repro.Repro baseline
