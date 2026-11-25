# Reproduces the PHP FTPS case: PHP CLI built from php/php-src @ 136e049 (8.5.12) with
# ./configure --disable-all --enable-cli --enable-ftp --with-openssl,
# then the PoC in poc/ run in baseline and control mode against the local MITM server.
#   docker build -t case-b-php-ftps .
#   docker run --rm case-b-php-ftps        # baseline then control
#   docker run --rm case-b-php-ftps sh poc/run.sh baseline
FROM debian:bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential autoconf bison re2c pkg-config libssl-dev python3 git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /case
RUN git init -q repo \
 && git -C repo remote add origin https://github.com/php/php-src \
 && git -C repo fetch -q --depth 1 origin 136e049ac10b032c83018e65b63b6df858943750 \
 && git -C repo checkout -q FETCH_HEAD

RUN cd repo \
 && ./buildconf --force \
 && ./configure --disable-all --enable-cli --enable-ftp --with-openssl \
 && make -j"$(nproc)" \
 && ./sapi/cli/php -v

COPY poc/ poc/

CMD ["sh", "-c", "sh poc/run.sh baseline; echo \"[baseline exit $?]\"; sh poc/run.sh control; echo \"[control exit $?]\""]
