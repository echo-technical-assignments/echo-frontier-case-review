# Reproduces the goth case: github.com/markbates/goth v1.82.0 (@ 6c7fc31) built into the PoC
# consumer in poc/, then run in baseline and control mode against a local identity provider.
#   docker build -t case-b-goth-oidc .
#   docker run --rm case-b-goth-oidc            # baseline then control
#   docker run --rm case-b-goth-oidc sh poc/run.sh baseline
FROM golang:1.23-bookworm

WORKDIR /case
RUN git clone https://github.com/markbates/goth repo \
 && git -C repo checkout 6c7fc319f1f5149273c813736418e5b27fce988e

COPY poc/ poc/

# The build step inside run.sh needs network access for Go module downloads (OFFLINE is empty).
ENV OFFLINE=
CMD ["sh", "-c", "sh poc/run.sh baseline; echo \"[baseline exit $?]\"; sh poc/run.sh control; echo \"[control exit $?]\""]
