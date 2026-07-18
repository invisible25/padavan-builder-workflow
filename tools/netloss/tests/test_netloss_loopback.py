#!/usr/bin/env python3
"""Loopback self-test for netloss.py. Pure Python (no shell) so it runs the same on Windows.

Usage: python test_netloss_loopback.py
"""
import csv
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

NETLOSS = str(Path(__file__).resolve().parent.parent / 'netloss.py')
PY = sys.executable


def run(args, timeout):
    return subprocess.run([PY, NETLOSS] + args, capture_output=True, text=True, timeout=timeout)


def read_statuses(log_path):
    with open(log_path, newline='', encoding='utf-8') as f:
        return [row['status'] for row in csv.DictReader(f)]


def check(name, condition):
    status = 'PASS' if condition else 'FAIL'
    print(f'[{status}] {name}')
    return condition


def test_udp_lossless(tmp_dir):
    port = 15005
    server = subprocess.Popen([PY, NETLOSS, 'udp-server', '--port', str(port)])
    time.sleep(0.3)
    try:
        log_path = tmp_dir / 'udp_lossless.csv'
        result = run(
            ['udp-client', '--host', '127.0.0.1', '--port', str(port),
             '--count', '50', '--interval', '0.05', '--log', str(log_path)],
            timeout=20,
        )
        statuses = read_statuses(log_path)
        ok = statuses.count('OK')
        return check(
            'UDP lossless: 50/50 OK',
            len(statuses) == 50 and ok == 50,
        )
    finally:
        server.terminate()
        server.wait(timeout=5)


def test_udp_drop_rate(tmp_dir):
    port = 15006
    server = subprocess.Popen([PY, NETLOSS, 'udp-server', '--port', str(port)])
    time.sleep(0.3)
    try:
        log_path = tmp_dir / 'udp_droprate.csv'
        run(
            ['udp-client', '--host', '127.0.0.1', '--port', str(port),
             '--count', '200', '--interval', '0.02', '--drop-rate', '0.2',
             '--log', str(log_path)],
            timeout=30,
        )
        statuses = read_statuses(log_path)
        lost = statuses.count('LOST')
        loss_pct = lost / len(statuses) * 100
        return check(
            f'UDP drop-rate 0.2 -> observed loss {loss_pct:.1f}% (expect 15-25%)',
            15.0 <= loss_pct <= 25.0,
        )
    finally:
        server.terminate()
        server.wait(timeout=5)


def test_dns_lossless(tmp_dir):
    # The udp echo server returns the full packet, so its first 2 bytes echo the
    # DNS transaction id -- exactly what the dns parser matches on.
    port = 15007
    server = subprocess.Popen([PY, NETLOSS, 'udp-server', '--port', str(port)])
    time.sleep(0.3)
    try:
        log_path = tmp_dir / 'dns_lossless.csv'
        run(
            ['dns', '--host', '127.0.0.1', '--port', str(port),
             '--count', '50', '--interval', '0.05', '--log', str(log_path)],
            timeout=20,
        )
        statuses = read_statuses(log_path)
        return check(
            'DNS lossless: 50/50 OK',
            len(statuses) == 50 and statuses.count('OK') == 50,
        )
    finally:
        server.terminate()
        server.wait(timeout=5)


def test_dns_drop_rate(tmp_dir):
    port = 15008
    server = subprocess.Popen([PY, NETLOSS, 'udp-server', '--port', str(port)])
    time.sleep(0.3)
    try:
        log_path = tmp_dir / 'dns_droprate.csv'
        run(
            ['dns', '--host', '127.0.0.1', '--port', str(port),
             '--count', '200', '--interval', '0.02', '--drop-rate', '0.3',
             '--log', str(log_path)],
            timeout=30,
        )
        statuses = read_statuses(log_path)
        lost = statuses.count('LOST')
        loss_pct = lost / len(statuses) * 100
        return check(
            f'DNS drop-rate 0.3 -> observed loss {loss_pct:.1f}% (expect 24-36%)',
            24.0 <= loss_pct <= 36.0,
        )
    finally:
        server.terminate()
        server.wait(timeout=5)


def test_tcp_success(tmp_dir):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0))
    listener.listen(5)
    port = listener.getsockname()[1]

    import threading

    def accept_loop():
        while True:
            try:
                conn, _ = listener.accept()
                conn.close()
            except OSError:
                return

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()
    try:
        log_path = tmp_dir / 'tcp_success.csv'
        run(
            ['tcp', '--host', '127.0.0.1', '--port', str(port),
             '--count', '20', '--interval', '0.1', '--log', str(log_path)],
            timeout=20,
        )
        statuses = read_statuses(log_path)
        return check(
            'TCP success: 20/20 OK',
            len(statuses) == 20 and statuses.count('OK') == 20,
        )
    finally:
        listener.close()


def test_tcp_refused(tmp_dir):
    log_path = tmp_dir / 'tcp_refused.csv'
    run(
        ['tcp', '--host', '127.0.0.1', '--port', '1',
         '--count', '5', '--interval', '0.1', '--timeout', '1', '--log', str(log_path)],
        timeout=20,
    )
    statuses = read_statuses(log_path)
    return check(
        'TCP refused: 5/5 REFUSED (not counted as loss)',
        len(statuses) == 5 and statuses.count('REFUSED') == 5,
    )


def main():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        results = [
            test_udp_lossless(tmp_dir),
            test_udp_drop_rate(tmp_dir),
            test_dns_lossless(tmp_dir),
            test_dns_drop_rate(tmp_dir),
            test_tcp_success(tmp_dir),
            test_tcp_refused(tmp_dir),
        ]
    if all(results):
        print('\nAll tests passed.')
        return 0
    print('\nSome tests FAILED.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
