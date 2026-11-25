# Reproduces the gson case: gson 2.11.0 (google/gson @ gson-parent-2.11.0) built with JDK 11 + Maven,
# then the PoC in poc/ run in baseline and control mode.
#   docker build -t case-a-gson .
#   docker run --rm case-a-gson            # baseline then control
#   docker run --rm case-a-gson sh poc/run.sh baseline
FROM maven:3.9.9-eclipse-temurin-11

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# poc/run.sh hard-codes JAVA_HOME=/opt/temurin-11-jdk
RUN ln -s "$JAVA_HOME" /opt/temurin-11-jdk

WORKDIR /case
RUN git clone https://github.com/google/gson repo \
 && git -C repo checkout 828a97be0f8d58108b140b77df8dc76b657f4a87

COPY poc/ poc/

# The build step inside run.sh needs network access for Maven dependencies (OFFLINE is empty).
ENV OFFLINE=
CMD ["sh", "-c", "sh poc/run.sh baseline; echo \"[baseline exit $?]\"; sh poc/run.sh control; echo \"[control exit $?]\""]
