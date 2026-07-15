#!/usr/bin/env python3
"""
anomaly_sniffer.py

A lightweight, real-time network anomaly detector.

Why this exists:
Most beginner sniffers just print packets. This one actually *thinks*
about the traffic — it tracks per-host packet rates in a sliding time
window and flags hosts that blow past a baseline (classic signature of
a port scan, SYN flood, or a compromised host beaconing out). No ML
model needed, just solid statistics and clean engineering.

Usage:
    sudo python3 anomaly_sniffer.py --iface eth0 --window 10 --threshold 100

Requires:
    pip install scapy
"""

import argparse
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP


@dataclass
class HostStats:
    """Rolling stats for a single source IP within the current window."""
    timestamps: deque = field(default_factory=deque)
    syn_count: int = 0
    ports_hit: set = field(default_factory=set)

    def prune(self, window_seconds: int):
        """Drop timestamps older than the sliding window."""
        cutoff = time.time() - window_seconds
        while self.timestamps and self.timestamps[0] < cutoff:
            self.timestamps.popleft()

    @property
    def rate(self) -> int:
        return len(self.timestamps)


class AnomalyDetector:
    def __init__(self, window: int, pps_threshold: int, port_threshold: int):
        self.window = window
        self.pps_threshold = pps_threshold
        self.port_threshold = port_threshold
        self.hosts: dict[str, HostStats] = defaultdict(HostStats)
        self.alerted: set[str] = set()  # avoid spamming the same host

    def handle_packet(self, pkt):
        if IP not in pkt:
            return

        src = pkt[IP].src
        stats = self.hosts[src]
        now = time.time()
        stats.timestamps.append(now)
        stats.prune(self.window)

        if TCP in pkt:
            stats.ports_hit.add(pkt[TCP].dport)
            if pkt[TCP].flags == "S":  # SYN, no ACK -> scan/flood signal
                stats.syn_count += 1
        elif UDP in pkt:
            stats.ports_hit.add(pkt[UDP].dport)

        self._evaluate(src, stats)

    def _evaluate(self, src: str, stats: HostStats):
        reasons = []

        if stats.rate > self.pps_threshold:
            reasons.append(f"{stats.rate} pkts in last {self.window}s (limit {self.pps_threshold})")

        if len(stats.ports_hit) > self.port_threshold:
            reasons.append(f"touched {len(stats.ports_hit)} distinct ports (possible port scan)")

        if reasons and src not in self.alerted:
            self._alert(src, reasons)
            self.alerted.add(src)
        elif not reasons and src in self.alerted:
            # host cooled off, allow future re-alerting
            self.alerted.discard(src)

    @staticmethod
    def _alert(src: str, reasons: list[str]):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n[!] {ts} ANOMALY from {src}")
        for r in reasons:
            print(f"    -> {r}")


def main():
    parser = argparse.ArgumentParser(description="Real-time network anomaly detector")
    parser.add_argument("--iface", default=None, help="Interface to sniff on (default: scapy auto-picks)")
    parser.add_argument("--window", type=int, default=10, help="Sliding window size in seconds")
    parser.add_argument("--pps", type=int, default=100, help="Packets/window threshold before flagging")
    parser.add_argument("--ports", type=int, default=15, help="Distinct-port threshold before flagging a scan")
    args = parser.parse_args()

    detector = AnomalyDetector(window=args.window, pps_threshold=args.pps, port_threshold=args.ports)

    print(f"[*] Watching {args.iface or 'default interface'} | window={args.window}s "
          f"pps_threshold={args.pps} port_threshold={args.ports}")
    print("[*] Ctrl+C to stop\n")

    try:
        sniff(iface=args.iface, prn=detector.handle_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    except PermissionError:
        print("[!] Run with sudo — raw sockets need root.")


if __name__ == "__main__":
    main()
