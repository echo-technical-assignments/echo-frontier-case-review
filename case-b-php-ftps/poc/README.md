# PoC: FTPS handshake in php ext/ftp performs no peer certificate verification

## What the PoC proves

`ftp_ssl_connect()` in the PHP `ftp` extension (`ext/ftp/ftp.c`, `ftp_login()`)
creates its OpenSSL client context with `SSL_CTX_new(SSLv23_client_method())`
and configures only `SSL_OP_ALL` and session-cache settings. There is no
`SSL_CTX_set_verify()`, no verify callback, no CA store load, and no hostname
check. OpenSSL's default verify mode on a manually created context is
`SSL_VERIFY_NONE`, so the `SSL_connect()` at `ext/ftp/ftp.c:297` accepts any
peer certificate, including a self-signed one.

The PoC runs a local MITM FTPS server (Python, `poc/mitm_server.py`) that
presents a freshly generated **self-signed certificate** with
`CN=not-the-real-server` and answers `AUTH TLS`. The PHP client
(`poc/poc.php`, run against the PHP CLI built from this commit) calls the
public API `ftp_ssl_connect()` + `ftp_login()`.

- **baseline**: the TLS handshake with the self-signed certificate completes
  (`TLS-HANDSHAKE-COMPLETED with self-signed cert`), `ftp_login()` returns
  `true`, and the MITM decrypts and logs the credentials from inside the
  tunnel: `[tls] USER ftpuser` and `[tls] PASS secret-PASSWORD`. The client
  never reports a certificate error.
- **control**: the same client uses plain `ftp_connect()` (no SSL). The
  control log shows `NO-AUTH-TLS-RECEIVED: client never upgraded to TLS` and
  `CONTROL-OK: no TLS handshake, no self-signed certificate accepted, no TLS
  credentials captured; the ssl_connect sink was not reached`.

So the effect is a full MITM credential capture: encryption without server
authentication (CWE-295).

## Base

- Repository: https://github.com/php/php-src
- Commit: `136e049ac10b032c83018e65b63b6df858943750` (PHP 8.5.12)
- Module built: PHP CLI (`sapi/cli/php`) configured with
  `./configure --disable-all --enable-cli --enable-ftp --with-openssl`,
  which enables `HAVE_FTP_SSL` in `ext/ftp`.
- Built artifact: `repo/sapi/cli/php`
  - SHA-256: `be9da17782203e6f2172eb00f663fb65e9f27bb872cd02d9da29bcc811b4f7d1`
- PHP reports: `PHP 8.5.12 (cli) (NTS)`

Note: the image had no `re2c` (needed by PHP's buildconf). `poc/run.sh`
builds re2c 4.6 from its upstream GitHub release tarball into `out/re2c-prefix`
and puts it on PATH, then runs `./buildconf --force` and `./configure` only
when `repo/sapi/cli/php` is missing. No other network access is required at
run time (the self-signed key/certificate are committed under `poc/`).

## Runs and results

| run | command | result |
| --- | --- | --- |
| baseline | `sh poc/run.sh baseline` | `VULNERABLE: ftp_ssl_connect() accepted a self-signed certificate and logged in over it`; MITM log shows the handshake completing and `PASS secret-PASSWORD` captured in plaintext on the attacker side. Exit 0. |
| control | `sh poc/run.sh control` | `CONTROL-OK: no TLS handshake, no self-signed certificate accepted, no TLS credentials captured; the ssl_connect sink was not reached`. Exit 0. |

## Reviewer steps

```
git clone https://github.com/php/php-src repo
git -C repo checkout 136e049ac10b032c83018e65b63b6df858943750
OFFLINE= sh poc/run.sh baseline
OFFLINE= sh poc/run.sh control
```

Run from the directory that holds `poc/` and `repo/`. Requires gcc, make,
autoconf, bison, pkg-config, libssl-dev, python3, and (fetched automatically
by the script from github.com) re2c.
