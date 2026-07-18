#!/usr/bin/env python3
"""ICMP-free packet loss diagnostic tool. See README.ru.md for usage."""
import argparse
import csv
import errno
import os
import random
import signal
import socket
import statistics
import struct
import sys
import threading
import time
from collections import Counter
from datetime import datetime

HEADER_FMT = '!IQ'
HEADER_SIZE = struct.calcsize(HEADER_FMT)


def csv_timestamp():
    return datetime.now().astimezone().isoformat(timespec='milliseconds')


def console_timestamp():
    return datetime.now().strftime('%H:%M:%S.%f')[:-3]


def default_log_name(prefix, host, port):
    safe_host = str(host).replace(':', '_').replace('/', '_')
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f'netloss_{prefix}_{safe_host}_{port}_{stamp}.csv'


def setup_signal_handler(stop_event):
    def handler(signum, frame):
        stop_event.set()
    signal.signal(signal.SIGINT, handler)


class CsvLogger:
    def __init__(self, path):
        self.path = path
        is_new = not os.path.exists(path) or os.path.getsize(path) == 0
        self._file = open(path, 'a', newline='', encoding='utf-8')
        self._writer = csv.writer(self._file)
        if is_new:
            self._writer.writerow(['timestamp', 'seq', 'rtt_ms', 'status'])
            self._file.flush()

    def write(self, seq, rtt_ms, status):
        rtt_str = f'{rtt_ms:.2f}' if rtt_ms is not None else ''
        self._writer.writerow([csv_timestamp(), seq, rtt_str, status])
        self._file.flush()

    def close(self):
        self._file.close()


class RollingWindow:
    """Flushes a stats summary every window_size probes or window_seconds, whichever comes first."""

    def __init__(self, window_size, window_seconds):
        self.window_size = window_size
        self.window_seconds = window_seconds
        self._reset()

    def _reset(self):
        self.entries = []
        self.start_perf = time.perf_counter()

    def add(self, seq, rtt_ms, status):
        self.entries.append((seq, rtt_ms, status))
        elapsed = time.perf_counter() - self.start_perf
        if len(self.entries) >= self.window_size or elapsed >= self.window_seconds:
            stats = self._compute_stats(elapsed)
            self._reset()
            return stats
        return None

    def _compute_stats(self, elapsed):
        counts = Counter(status for _, _, status in self.entries)
        rtts = [rtt for _, rtt, _ in self.entries if rtt is not None]
        jitter = None
        if len(rtts) >= 2:
            diffs = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
            jitter = statistics.mean(diffs)
        return {
            'seq_start': self.entries[0][0],
            'seq_end': self.entries[-1][0],
            'count': len(self.entries),
            'elapsed': elapsed,
            'counts': counts,
            'avg_rtt': statistics.mean(rtts) if rtts else None,
            'jitter': jitter,
            'min_rtt': min(rtts) if rtts else None,
            'max_rtt': max(rtts) if rtts else None,
        }


class TotalStats:
    """Same aggregate fields as RollingWindow, kept incrementally for the whole run."""

    def __init__(self):
        self.counts = Counter()
        self.seq_first = None
        self.seq_last = None
        self.rtt_sum = 0.0
        self.rtt_count = 0
        self.rtt_min = None
        self.rtt_max = None
        self._last_rtt = None
        self.jitter_sum = 0.0
        self.jitter_count = 0

    def add(self, seq, rtt_ms, status):
        self.counts[status] += 1
        self.seq_first = seq if self.seq_first is None else self.seq_first
        self.seq_last = seq
        if rtt_ms is not None:
            self.rtt_sum += rtt_ms
            self.rtt_count += 1
            self.rtt_min = rtt_ms if self.rtt_min is None else min(self.rtt_min, rtt_ms)
            self.rtt_max = rtt_ms if self.rtt_max is None else max(self.rtt_max, rtt_ms)
            if self._last_rtt is not None:
                self.jitter_sum += abs(rtt_ms - self._last_rtt)
                self.jitter_count += 1
            self._last_rtt = rtt_ms

    @property
    def total(self):
        return sum(self.counts.values())

    @property
    def avg_rtt(self):
        return self.rtt_sum / self.rtt_count if self.rtt_count else None

    @property
    def jitter(self):
        return self.jitter_sum / self.jitter_count if self.jitter_count else None


def fmt_rtt(v):
    return f'{v:.1f}ms' if v is not None else '-'


def fmt_range(counts, keys):
    return sum(counts.get(k, 0) for k in keys)


# ---------------------------------------------------------------------------
# tcp subcommand
# ---------------------------------------------------------------------------

TCP_LOSS_STATUSES = ('TIMEOUT', 'UNREACHABLE')


def is_tcp_loss(status):
    return status in TCP_LOSS_STATUSES or status.startswith('ERROR')


def tcp_probe(host, port, timeout):
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        return 'ERROR:dns', None
    last_err = None
    for family, socktype, proto, _canon, sockaddr in infos:
        try:
            with socket.socket(family, socktype, proto) as s:
                s.settimeout(timeout)
                s.connect(sockaddr)
                return 'OK', (time.perf_counter() - t0) * 1000
        except socket.timeout:
            return 'TIMEOUT', None
        except ConnectionRefusedError:
            return 'REFUSED', None
        except OSError as e:
            if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
                return 'UNREACHABLE', None
            last_err = e
            continue
    return f'ERROR:{last_err}', None


def print_tcp_window(summary):
    c = summary['counts']
    loss = fmt_range(c, TCP_LOSS_STATUSES) + sum(v for k, v in c.items() if k.startswith('ERROR'))
    loss_pct = loss / summary['count'] * 100
    print(
        f"--- window seq {summary['seq_start']}-{summary['seq_end']} "
        f"({summary['count']} probes, {summary['elapsed']:.1f}s): "
        f"loss={loss_pct:.1f}% ({c.get('TIMEOUT', 0)} timeout, {c.get('REFUSED', 0)} refused, "
        f"{c.get('UNREACHABLE', 0)} unreachable) | avg_rtt={fmt_rtt(summary['avg_rtt'])} "
        f"jitter={fmt_rtt(summary['jitter'])} min/max={fmt_rtt(summary['min_rtt'])}/{fmt_rtt(summary['max_rtt'])} ---"
    )


def print_tcp_total(totals):
    c = totals.counts
    loss = fmt_range(c, TCP_LOSS_STATUSES) + sum(v for k, v in c.items() if k.startswith('ERROR'))
    loss_pct = loss / totals.total * 100 if totals.total else 0.0
    print(
        f"=== TOTAL seq {totals.seq_first}-{totals.seq_last} ({totals.total} probes): "
        f"loss={loss_pct:.1f}% ({c.get('TIMEOUT', 0)} timeout, {c.get('REFUSED', 0)} refused, "
        f"{c.get('UNREACHABLE', 0)} unreachable) | avg_rtt={fmt_rtt(totals.avg_rtt)} "
        f"jitter={fmt_rtt(totals.jitter)} min/max={fmt_rtt(totals.rtt_min)}/{fmt_rtt(totals.rtt_max)} ==="
    )


def run_tcp(args):
    stop_event = threading.Event()
    setup_signal_handler(stop_event)
    log_path = args.log or default_log_name('tcp', args.host, args.port)
    logger = CsvLogger(log_path)
    window = RollingWindow(args.window_size, args.window_seconds)
    totals = TotalStats()
    print(f'Logging to {log_path}')

    start = time.perf_counter()
    seq = 0
    try:
        while not stop_event.is_set() and (args.count is None or seq < args.count):
            tick_target = start + seq * args.interval
            wait = tick_target - time.perf_counter()
            if wait > 0 and stop_event.wait(wait):
                break

            status, rtt_ms = tcp_probe(args.host, args.port, args.timeout)
            print(f'[{console_timestamp()}] seq={seq:<6} {status:<10} rtt={fmt_rtt(rtt_ms)}')
            logger.write(seq, rtt_ms, status)
            totals.add(seq, rtt_ms, status)
            summary = window.add(seq, rtt_ms, status)
            if summary:
                print_tcp_window(summary)
            seq += 1
    finally:
        if totals.total:
            print_tcp_total(totals)
        logger.close()


# ---------------------------------------------------------------------------
# udp-server subcommand
# ---------------------------------------------------------------------------

def run_udp_server(args):
    stop_event = threading.Event()
    setup_signal_handler(stop_event)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    sock.settimeout(0.5)
    print(f'UDP echo server listening on {args.bind}:{args.port} (Ctrl+C to stop)')
    count = 0
    try:
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            sock.sendto(data, addr)
            count += 1
            if count % 100 == 0:
                print(f'echoed {count} packets')
    finally:
        print(f'Total echoed: {count}')
        sock.close()


# ---------------------------------------------------------------------------
# udp-client subcommand
# ---------------------------------------------------------------------------

def print_udp_window(summary):
    c = summary['counts']
    lost = c.get('LOST', 0)
    loss_pct = lost / summary['count'] * 100
    print(
        f"--- window seq {summary['seq_start']}-{summary['seq_end']} "
        f"({summary['count']} pkts, {summary['elapsed']:.1f}s): "
        f"loss={loss_pct:.1f}% ({lost} lost, {c.get('LATE', 0)} late) | "
        f"avg_rtt={fmt_rtt(summary['avg_rtt'])} jitter={fmt_rtt(summary['jitter'])} "
        f"min/max={fmt_rtt(summary['min_rtt'])}/{fmt_rtt(summary['max_rtt'])} ---"
    )


def print_udp_total(totals):
    c = totals.counts
    lost = c.get('LOST', 0)
    loss_pct = lost / totals.total * 100 if totals.total else 0.0
    print(
        f"=== TOTAL seq {totals.seq_first}-{totals.seq_last} ({totals.total} pkts): "
        f"loss={loss_pct:.1f}% ({lost} lost, {c.get('LATE', 0)} late) | "
        f"avg_rtt={fmt_rtt(totals.avg_rtt)} jitter={fmt_rtt(totals.jitter)} "
        f"min/max={fmt_rtt(totals.rtt_min)}/{fmt_rtt(totals.rtt_max)} ==="
    )


class UdpClientRun:
    def __init__(self, args, sock, target, logger, window, totals):
        self.args = args
        self.sock = sock
        self.target = target
        self.logger = logger
        self.window = window
        self.totals = totals
        self.outstanding = {}
        self.finalized = set()
        padding_len = max(args.payload_size, HEADER_SIZE) - HEADER_SIZE
        self.padding = b'\x00' * padding_len

    def _emit(self, seq, rtt_ms, status):
        print(f'[{console_timestamp()}] seq={seq:<6} {status:<6} rtt={fmt_rtt(rtt_ms)}')
        self.logger.write(seq, rtt_ms, status)
        self.totals.add(seq, rtt_ms, status)
        summary = self.window.add(seq, rtt_ms, status)
        if summary:
            print_udp_window(summary)

    def send_next(self, seq):
        send_ts_ns = time.perf_counter_ns()
        if self.args.drop_rate <= 0 or random.random() >= self.args.drop_rate:
            packet = struct.pack(HEADER_FMT, seq, send_ts_ns) + self.padding
            self.sock.sendto(packet, self.target)
        self.outstanding[seq] = send_ts_ns

    def try_receive(self):
        try:
            data, _addr = self.sock.recvfrom(2048)
        except socket.timeout:
            return
        recv_ns = time.perf_counter_ns()
        if len(data) < HEADER_SIZE:
            return
        r_seq, r_send_ns = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
        rtt_ms = (recv_ns - r_send_ns) / 1e6
        status = 'LATE' if r_seq in self.finalized else 'OK'
        self.outstanding.pop(r_seq, None)
        self.finalized.add(r_seq)
        self._emit(r_seq, rtt_ms, status)

    def check_timeouts(self):
        now_ns = time.perf_counter_ns()
        timeout_ns = int(self.args.timeout * 1e9)
        expired = [s for s, ts in self.outstanding.items() if now_ns - ts > timeout_ns]
        for s in expired:
            self.outstanding.pop(s)
            self.finalized.add(s)
            self._emit(s, None, 'LOST')

    def finalize_remaining(self):
        for s in list(self.outstanding.keys()):
            self.outstanding.pop(s)
            self.finalized.add(s)
            self._emit(s, None, 'LOST')


def run_udp_client(args):
    stop_event = threading.Event()
    setup_signal_handler(stop_event)
    log_path = args.log or default_log_name('udp', args.host, args.port)
    logger = CsvLogger(log_path)
    window = RollingWindow(args.window_size, args.window_seconds)
    totals = TotalStats()
    print(f'Logging to {log_path}')

    infos = socket.getaddrinfo(args.host, args.port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    family, socktype, proto, _canon, sockaddr = infos[0]
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(0.05)

    run = UdpClientRun(args, sock, sockaddr, logger, window, totals)

    start = time.perf_counter()
    end_time = start + args.duration if args.duration is not None else None
    seq = 0
    grace_deadline = None

    try:
        while not stop_event.is_set():
            can_send = (args.count is None or seq < args.count) and (end_time is None or time.perf_counter() < end_time)
            if can_send:
                tick_target = start + seq * args.interval
                if time.perf_counter() >= tick_target:
                    run.send_next(seq)
                    seq += 1
            else:
                if grace_deadline is None:
                    grace_deadline = time.perf_counter() + args.timeout + 0.1
                if not run.outstanding or time.perf_counter() >= grace_deadline:
                    break

            run.try_receive()
            run.check_timeouts()
    finally:
        run.finalize_remaining()
        if totals.total:
            print_udp_total(totals)
        logger.close()
        sock.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog='netloss.py',
        description='ICMP-free packet loss diagnostic tool (see README.ru.md).',
    )
    sub = parser.add_subparsers(dest='command', required=True)

    p_tcp = sub.add_parser('tcp', help='TCP connect-probe to any IP:port (no server component needed)')
    p_tcp.add_argument('--host', required=True)
    p_tcp.add_argument('--port', required=True, type=int)
    p_tcp.add_argument('--interval', type=float, default=1.0)
    p_tcp.add_argument('--timeout', type=float, default=2.0)
    p_tcp.add_argument('--count', type=int, default=None)
    p_tcp.add_argument('--log', default=None)
    p_tcp.add_argument('--window-size', type=int, default=20)
    p_tcp.add_argument('--window-seconds', type=float, default=10.0)
    p_tcp.set_defaults(func=run_tcp)

    p_udps = sub.add_parser('udp-server', help='UDP echo server - run on a host you control (e.g. your VPS/VPN server)')
    p_udps.add_argument('--port', required=True, type=int)
    p_udps.add_argument('--bind', default='0.0.0.0')
    p_udps.set_defaults(func=run_udp_server)

    p_udpc = sub.add_parser('udp-client', help='UDP echo client - recommended ground-truth loss measurement')
    p_udpc.add_argument('--host', required=True)
    p_udpc.add_argument('--port', required=True, type=int)
    p_udpc.add_argument('--interval', type=float, default=0.2)
    p_udpc.add_argument('--timeout', type=float, default=1.0)
    p_udpc.add_argument('--duration', type=float, default=None)
    p_udpc.add_argument('--count', type=int, default=None)
    p_udpc.add_argument('--payload-size', type=int, default=64)
    p_udpc.add_argument('--log', default=None)
    p_udpc.add_argument('--window-size', type=int, default=20)
    p_udpc.add_argument('--window-seconds', type=float, default=10.0)
    p_udpc.add_argument('--drop-rate', type=float, default=0.0, help=argparse.SUPPRESS)
    p_udpc.set_defaults(func=run_udp_client)

    return parser


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
