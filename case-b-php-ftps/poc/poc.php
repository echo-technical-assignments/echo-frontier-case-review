<?php
/*
 * PoC client for the ftp ext of PHP 8.5.12 @ 136e049.
 *
 * baseline: ftp_ssl_connect() + ftp_login() against a MITM FTPS server that
 *           presents a self-signed certificate for CN=not-the-real-server.
 * control:  plain ftp_connect() + ftp_login() against the same server; no
 *           SSL is requested, so no TLS handshake ever happens.
 *
 * argv[1] = mode (baseline|control), argv[2] = port.
 */
$mode = $argv[1] ?? 'baseline';
$port = $argv[2] ?? '2121';
$host = '127.0.0.1';

echo "mode=$mode PHP=" . PHP_VERSION . "\n";

if ($mode === 'baseline') {
    echo "calling ftp_ssl_connect($host, $port)...\n";
    $ftp = ftp_ssl_connect($host, (int)$port, 15);
} else {
    echo "calling ftp_connect($host, $port) (no SSL requested)...\n";
    $ftp = ftp_connect($host, (int)$port, 15);
}

if ($ftp === false) {
    echo "connect FAILED\n";
    exit(1);
}

echo "connect returned an FTP\\Connection object; calling ftp_login(user, secret-PASSWORD)...\n";
$ok = @ftp_login($ftp, 'ftpuser', 'secret-PASSWORD');
echo "ftp_login() => " . var_export($ok, true) . "\n";
echo "systype: " . var_export(@ftp_systype($ftp), true) . "\n";

if ($mode === 'baseline') {
    if ($ok === true) {
        echo "VULNERABLE: ftp_ssl_connect() accepted a self-signed certificate and logged in over it\n";
    } else {
        echo "NOT VULNERABLE: login did not succeed\n";
    }
} else {
    echo "CONTROL: plain FTP login (expected, no TLS involved)\n";
}
ftp_close($ftp);
