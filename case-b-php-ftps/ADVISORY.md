# The ftp extension's FTPS client performs no peer certificate verification, allowing a MITM to capture credentials

Draft report to the project's private vulnerability reporting form
(https://github.com/php/php-src/security/advisories/new).

| Field | Value |
|---|---|
| Package | php-src |
| Affected | all releases that share the current `ext/ftp` TLS code path (8.5.12 tested) |
| Patched | None |
| Severity | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` (7.4 High) |
| CWEs | CWE-295 |

### Summary

`ftp_login()` in `ext/ftp/ftp.c` upgrades an `ftp_ssl_connect()` connection to TLS with a client
context that never verifies the peer certificate, so any certificate — including a self-signed one
for a name that is not the server's — completes the handshake. We ran
`ftp_ssl_connect()` + `ftp_login()` against a local MITM FTPS server presenting a self-signed
certificate (`CN=not-the-real-server`): the handshake completed, `ftp_login()` returned true, and
the MITM logged `[tls] USER ftpuser` and `[tls] PASS secret-PASSWORD` in plaintext, with no
certificate warning on the client.

The TLS client context is created at `ext/ftp/ftp.c:271` with only `SSL_OP_ALL` and session-cache
settings; no `SSL_CTX_set_verify()`, CA store or hostname check precedes `SSL_connect()` at
`ext/ftp/ftp.c:297`.

#### Reachability

- **Entry points:** `ftp_ssl_connect()` followed by `ftp_login()`; the `ftps://` stream wrapper
  sets `use_ssl` on the same `ftpbuf_t` and reaches the same code (read, not run)
- **Doesn't help:** there is no ftp-extension setting or stream context option that turns
  verification on or supplies a CA bundle — the API offers no remedy

### Impact

Any PHP application that logs in over `ftp_ssl_connect()` or the `ftps://` stream wrapper, on a
build with FTP-SSL support, sends its FTP credentials to whoever can intercept the connection. The
attacker chooses the network position and the certificate; everything else is the client's normal
behaviour.

### CVE request

Please assign a CVE for this, with the affected range above and CWE-295.

On classification: the function's documentation states that "The connection established by
ftp_ssl_connect() will not do peer-certificate verification", and the security policy excludes
"the use of legacy APIs or settings known to be insecure, particularly those documented as such,
or those with a secure alternative". We report it anyway because the policy also classifies as
security issues bugs that "allow users to execute unauthorized actions" or "access data that is
not intended to be accessible", and this one captures credentials sent through an API whose name
and documentation promise a secure connection. The policy's own secure-alternative test is also
not met inside the extension: `ftps://` and `ftp_ssl_connect()` are the only FTPS entry points,
both share this code, and neither offers a CA bundle or verification option, so an application
cannot configure its way out. The classification is yours to make.

### Fix status

- **Upstream fix:** none; no CVE or GHSA as of 2026-11-02.
- **Suggested fix:** in `ftp_login()`, load the default CA store, set
  `SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL)` and the expected peer name before
  `SSL_connect()`, failing the login when verification fails — the same trust model
  `ext/openssl/xp_ssl.c` already applies to the stream wrappers (`not tested`).
