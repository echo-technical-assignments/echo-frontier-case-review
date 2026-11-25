## Summary

**The library.** PHP is the PHP language interpreter; the `ftp` extension is its client-side FTP
and FTPS support. The functions that matter here are client-side: `ftp_ssl_connect()` opens an
FTPS control connection and `ftp_login()` upgrades it to TLS and authenticates.

**The defect.** `ftp_ssl_connect()` promises a secure FTPS connection. When `ftp_login()` upgrades
that connection to TLS, it builds the OpenSSL client context itself and configures only
compatibility flags and a session cache: **it never asks OpenSSL to verify the server's
certificate**. No verification callback is registered, no CA store is loaded, and the server
hostname is never checked against the certificate.

The context therefore keeps OpenSSL's default verify mode, in which the handshake succeeds against
any peer certificate, including a self-signed one for a name that is not the server's. The
application has no way to change this: **the FTP extension exposes no setting or API to supply a
CA bundle or turn verification on**, so the missing check cannot be repaired from userland.

The result is encryption without authentication. The tunnel is real TLS, but it is equally happy
to terminate on an attacker, so it protects the credentials from passive observers only — the
party that terminated the handshake reads them in plaintext.

**The attack.** An attacker positioned on the network path between the PHP application and its FTP
server intercepts the TCP connection and answers the client's `AUTH TLS` with a self-signed
certificate. `ftp_login()` completes the handshake and sends the username and password inside the
attacker's tunnel, **and the attacker reads both in plaintext**; the client raises no certificate
warning. No malicious input reaches the application — the victim only has to log in to its usual
FTPS server through the attacker's network position.

### How it breaks

**In one line:** the FTPS client never verifies the server's certificate, so a machine-in-the-middle
can terminate the TLS handshake itself and read the credentials.

```
Input:  the legitimate login to the usual FTPS server, through an attacker on the path

ftp_login(), control connection:
  AUTH TLS sent; the attacker accepts the upgrade
          │
          ├─ TLS client context created with only compatibility
          │  flags and session-cache settings
          │     → verify mode stays "accept any certificate",
          │        no CA store, no hostname check
          │
          └─ handshake completes against the attacker's self-signed cert
                → USER and PASS sent inside the attacker's tunnel   ← the bug
```

### Terms

| Term | What it means here |
|---|---|
| FTPS | FTP over an explicit TLS upgrade: the client sends `AUTH TLS` and the control connection switches to TLS |
| control connection | the FTP command channel; `USER`/`PASS` travel on it |
| self-signed certificate | a certificate the attacker generates itself, for any name — here `CN=not-the-real-server` |
| MITM | a machine-in-the-middle: an attacker on the network path who terminates the TLS handshake |

### What it looks like

**The setup.** A PHP application moves files over FTPS with the `ftp` extension: one
`ftp_ssl_connect()` to the server, then `ftp_login()` with credentials. This is a common pattern;
no real service was tested.

```php
$ftp = ftp_ssl_connect($host, $port, 15);
ftp_login($ftp, 'ftpuser', 'secret-PASSWORD');
```

**What we ran.** `ftp_ssl_connect()` + `ftp_login()` against a local MITM FTPS server presenting a
self-signed certificate with `CN=not-the-real-server`, on PHP built from `8.5.12 @ 136e049`
(configured `--enable-ftp --with-openssl`). Condensed from `poc/poc.php`, with the same calls and
arguments:

```php
$ftp = ftp_ssl_connect('127.0.0.1', $port, 15);
$ok  = ftp_login($ftp, 'ftpuser', 'secret-PASSWORD');
```

| Input | 8.5.12 @ 136e049 |
|---|---|
| `ftp_ssl_connect()` + `ftp_login()`, self-signed MITM certificate | **handshake completed, login `true`, MITM logged `PASS secret-PASSWORD`** |
| control: `ftp_connect()` + `ftp_login()`, same server | no TLS handshake; credentials stayed on the plaintext channel |

Captured lines (`logs/baseline.stdout.log`):

```
ftp_login() => true
TLS-HANDSHAKE-COMPLETED with self-signed cert
[tls] USER ftpuser
[tls] PASS secret-PASSWORD
```

The client emitted no certificate error or warning (`logs/baseline.stderr.log` is empty). The
control run used plain `ftp_connect()` and no TLS handshake occurred — the MITM logged
`NO-AUTH-TLS-RECEIVED: client never upgraded to TLS` — so the effect depends solely on the
`ftp_ssl_connect()` TLS path (`logs/control.stdout.log`). Reproduce both with `poc/run.sh`.

**Not shown:** a real deployment, real credentials, and the data-channel transfer of files (the
code path reads that the data channel is negotiated on the same unverified handle;
it was not run).

### Am I affected?

**Yes**, if your PHP is built with FTP-SSL support (`--enable-ftp` with `--with-openssl`,
`HAVE_FTP_SSL` defined) and your application logs in over `ftp_ssl_connect()` or the `ftps://`
stream wrapper, on `php` sharing this code path (8.5.12 tested).

**No**, if:
- your PHP is built without FTP-SSL support (`ftp_ssl_connect()` does not exist);
- your application only uses plain FTP or other transports;
- you use SFTP via the ssh2 extension instead — a different protocol and code path.

Turning TLS on with `ftp_ssl_connect()` doesn't help by itself: it is exactly the call that
produces the unverified handshake.

### What this does not claim

- **Impact:** the run shows a MITM reading the FTP credentials; file contents were not transferred
  or read in the run.
- **Tested on:** one build, PHP 8.5.12 from commit `136e049`, configured
  `--disable-all --enable-cli --enable-ftp --with-openssl`, Linux aarch64; no other SAPI, version,
  OS or OpenSSL configuration was run.
- **Versions run:** only 8.5.12. The affected range is inferred from the code at the tested commit;
  no other release was run.
- **Not run end to end:** the data channel was not encrypted or used in the run; its negotiation on
  the same unverified handle is read from the code, not run.
- **Policy:** the documentation states that `ftp_ssl_connect()` does not do peer-certificate
  verification; this report argues the behaviour is a security defect regardless, since the extension
  offers no API to supply a CA bundle or enable verification.

## At a glance

| | |
|---|---|
| Package | `php` (deb) |
| Where | the TLS client context in `ftp_login()` in `ext/ftp/ftp.c` |
| Affected | every release sharing this code path (8.5.12 tested) |
| Fixed | none |
| Public ID | none (no CVE, no GHSA), checked 2026-11-02 |
| CWE | CWE-295, Improper Certificate Validation |
| CVSS 3.1 | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` → **7.4 (High)** |

### Why this vector

| Metric | Value | Why |
|---|---|---|
| Attack Vector | Network | the attacker is on the network path between the client and its FTP server |
| Attack Complexity | High | the attack needs a machine-in-the-middle position on that path |
| Privileges Required | None | only network reachability, no privileges on the client or server |
| User Interaction | None | the application logs in on its own; no user action is needed |
| Scope | Unchanged | the attacker gets the FTP credentials and session, not the PHP process |
| Confidentiality | High | the run shows the username and password read in plaintext by the MITM |
| Integrity | High | the attacker holds the whole session: commands, listings and transfers |
| Availability | None | nothing in the run degrades or halts the client |

## Verification

### Is this already known?

No public advisory covers it: no CVE and no GHSA as of 2026-11-02. The function's own documentation
(`php.net/manual/en/function.ftp-ssl-connect.php`) does state the behaviour, which argues the
project knows the code does no verification — this report argues it is a security defect with no
userland remedy.

### Is it still unfixed?

Yes. The checkout at `136e049` (8.5.12) has no `SSL_CTX_set_verify`, no CA store load and no
hostname check in `ext/ftp/ftp.c`'s `ftp_login()`; `SSL_CTX_set_verify` appears nowhere in
`ext/ftp/`, only in `ext/openssl/xp_ssl.c` (read, not run). Checked against commit `136e049` on
2026-11-02.

### What does upstream think?

The security policy classifies as security issues bugs that "allow users to execute unauthorized
actions" or "access data that is not intended to be accessible" — credential capture fits both.
Its "not a security issue" list covers malicious code, unsanitized arguments and known-insecure
settings; none names an unverified TLS handshake. One item excludes "the use of legacy APIs or
settings known to be insecure, particularly those documented as such": the function's
documentation does disclose the missing verification, so the classification is a judgement call
this report leaves to the maintainers (read, not run).
