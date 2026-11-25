# Logs

All files produced by `sh poc/run.sh baseline` / `sh poc/run.sh control` from
the workspace root, against the PHP CLI built from
php/php-src @ `136e049ac10b032c83018e65b63b6df858943750` (8.5.12).

Built artifact (named in both logs): `repo/sapi/cli/php`,
SHA-256 `be9da17782203e6f2172eb00f663fb65e9f27bb872cd02d9da29bcc811b4f7d1`.

- `baseline.stdout.log` — command:
  `sh poc/run.sh baseline > logs/baseline.stdout.log 2> logs/baseline.stderr.log` (exit 0).
  Shows `ftp_ssl_connect()` + `ftp_login()` succeeding over a self-signed
  certificate, and the MITM server log capturing `TLS-HANDSHAKE-COMPLETED with
  self-signed cert`, `[tls] USER ftpuser`, `[tls] PASS secret-PASSWORD`, ending
  with `EFFECT-PRESENT: the TLS handshake with a self-signed certificate
  completed and the MITM captured the credentials`.
- `baseline.stderr.log` — empty (the client produced no certificate warnings;
  the two `ftp_close()` warnings about SSL write/shutdown appear on stdout
  because they are PHP warnings emitted after the MITM already exited).
- `control.stdout.log` — command:
  `sh poc/run.sh control > logs/control.stdout.log 2> logs/control.stderr.log` (exit 0).
  Shows the plain `ftp_connect()` run, `NO-AUTH-TLS-RECEIVED: client never
  upgraded to TLS`, and `CONTROL-OK: no TLS handshake, no self-signed
  certificate accepted, no TLS credentials captured; the ssl_connect sink was
  not reached`.
- `control.stderr.log` — empty.
- `commands.jsonl` — the two commands above with their exit codes.
