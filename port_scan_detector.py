#!/usr/bin/env python3
"""
Enhanced Port Scan Detection Tool using Scapy

Detects:
- Multiple ports accessed by the same source IP within a sliding time window
- Sequential scanning behavior (e.g., 20,21,22,23...)
- Distributed scans from multiple sources
- Various scan patterns (aggressive vs. slow scans)

Enhancements:
- Root privilege validation
- Memory management and cleanup
- IP whitelisting
- Severity levels
- Destination IP tracking
- Better error handling
- Performance optimizations
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Deque, Dict, Set, Tuple, Optional
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, conf  # type: ignore
except ImportError:
    print("[!] Scapy not found. Install with: pip install scapy", file=sys.stderr)
    sys.exit(1)


@dataclass
class Alert:
    ts: float
    timestamp: str
    src_ip: str
    unique_ports: int
    window_seconds: int
    reason: str
    severity: str
    sample_ports: list[int]
    dst_ips: list[str]
    total_attempts: int


class PortScanDetector:
    def __init__(
        self,
        window_seconds: int = 10,
        unique_port_threshold: int = 20,
        sequential_threshold: int = 10,
        cooldown_seconds: int = 30,
        log_file: Optional[str] = None,
        exec_cmd: Optional[str] = None,
        bpf_filter: str = "tcp",
        whitelist_ips: Optional[Set[str]] = None,
        cleanup_interval: int = 300,
        max_inactive_time: int = 600,
    ):
        self.window_seconds = window_seconds
        self.unique_port_threshold = unique_port_threshold
        self.sequential_threshold = sequential_threshold
        self.cooldown_seconds = cooldown_seconds
        self.log_file = log_file
        self.exec_cmd = exec_cmd
        self.bpf_filter = bpf_filter
        self.whitelist_ips = whitelist_ips or set()
        self.cleanup_interval = cleanup_interval
        self.max_inactive_time = max_inactive_time

        # src_ip -> deque of (timestamp, dst_port, dst_ip)
        self.attempts: Dict[str, Deque[Tuple[float, int, str]]] = defaultdict(deque)

        # Track scan targets: dst_ip -> set of src_ips
        self.scan_targets: Dict[str, Set[str]] = defaultdict(set)

        # Cooldown to prevent alert spam: src_ip -> last_alert_ts
        self.last_alert: Dict[str, float] = {}

        # Last cleanup timestamp
        self.last_cleanup: float = time.time()

        # Statistics
        self.stats = {
            "packets_processed": 0,
            "alerts_generated": 0,
            "whitelisted_filtered": 0,
        }

    def _cleanup_old(self, src_ip: str, now: float) -> None:
        """Remove entries outside the sliding window for a specific IP."""
        dq = self.attempts[src_ip]
        while dq and (now - dq[0][0]) > self.window_seconds:
            dq.popleft()

    def _cleanup_inactive_ips(self, now: float) -> None:
        """Remove inactive IPs to prevent memory growth."""
        if (now - self.last_cleanup) < self.cleanup_interval:
            return

        inactive_ips = [
            ip
            for ip, dq in self.attempts.items()
            if not dq or (now - dq[-1][0]) > self.max_inactive_time
        ]

        for ip in inactive_ips:
            del self.attempts[ip]
            if ip in self.last_alert:
                del self.last_alert[ip]

        # Cleanup scan targets
        inactive_targets = [
            dst_ip
            for dst_ip, src_set in self.scan_targets.items()
            if not src_set
        ]
        for dst_ip in inactive_targets:
            del self.scan_targets[dst_ip]

        self.last_cleanup = now
        if inactive_ips:
            print(f"[*] Cleaned up {len(inactive_ips)} inactive IPs")

    @staticmethod
    def _is_syn_only(tcp_flags: int) -> bool:
        """Check if packet is SYN without ACK (connection attempt)."""
        SYN = 0x02
        ACK = 0x10
        return (tcp_flags & SYN) != 0 and (tcp_flags & ACK) == 0

    @staticmethod
    def _has_sequential_run(ports: Set[int], min_len: int) -> bool:
        """Detect sequential port scanning pattern."""
        if len(ports) < min_len:
            return False
        sorted_ports = sorted(ports)
        run = 1
        for i in range(1, len(sorted_ports)):
            if sorted_ports[i] == sorted_ports[i - 1] + 1:
                run += 1
                if run >= min_len:
                    return True
            else:
                run = 1
        return False

    def _in_cooldown(self, src_ip: str, now: float) -> bool:
        """Check if source IP is in alert cooldown period."""
        last = self.last_alert.get(src_ip)
        return last is not None and (now - last) < self.cooldown_seconds

    def _determine_severity(
        self, unique_ports: int, is_sequential: bool, scan_rate: float
    ) -> str:
        """Determine alert severity based on scan characteristics."""
        if unique_ports >= 50 or scan_rate > 20:
            return "CRITICAL"
        elif unique_ports >= 30 or is_sequential:
            return "HIGH"
        elif unique_ports >= 20:
            return "MEDIUM"
        else:
            return "LOW"

    def _emit_alert(self, alert: Alert) -> None:
        """Generate and log security alert."""
        # Console with color coding
        severity_colors = {
            "CRITICAL": "\033[91m",  # Red
            "HIGH": "\033[93m",  # Yellow
            "MEDIUM": "\033[94m",  # Blue
            "LOW": "\033[92m",  # Green
        }
        reset_color = "\033[0m"
        color = severity_colors.get(alert.severity, "")

        print(
            f"{color}[ALERT-{alert.severity}]{reset_color} "
            f"src={alert.src_ip} "
            f"unique_ports={alert.unique_ports} "
            f"attempts={alert.total_attempts} "
            f"window={alert.window_seconds}s "
            f"reason={alert.reason} "
            f"sample_ports={alert.sample_ports[:10]}"
        )

        # Log file (JSON lines)
        if self.log_file:
            try:
                os.makedirs(os.path.dirname(self.log_file) or ".", exist_ok=True)
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(asdict(alert), ensure_ascii=False) + "\n")
            except IOError as e:
                print(f"[!] Failed to write to log file: {e}", file=sys.stderr)

        # Optional command hook
        if self.exec_cmd:
            env = os.environ.copy()
            env.update(
                {
                    "PSD_SRC_IP": alert.src_ip,
                    "PSD_UNIQUE_PORTS": str(alert.unique_ports),
                    "PSD_REASON": alert.reason,
                    "PSD_SEVERITY": alert.severity,
                    "PSD_SAMPLE_PORTS": ",".join(map(str, alert.sample_ports)),
                }
            )
            try:
                subprocess.Popen(
                    self.exec_cmd, shell=True, env=env, 
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except Exception as e:
                print(f"[!] Failed to execute command hook: {e}", file=sys.stderr)

        self.stats["alerts_generated"] += 1

    def process_packet(self, pkt) -> None:
        """Process individual network packet."""
        try:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return

            ip = pkt[IP]
            tcp = pkt[TCP]

            # Only consider SYN packets (new connection attempts)
            if not self._is_syn_only(int(tcp.flags)):
                return

            now = time.time()
            src_ip = ip.src
            dst_ip = ip.dst
            dst_port = int(tcp.dport)

            self.stats["packets_processed"] += 1

            # Whitelist check
            if src_ip in self.whitelist_ips:
                self.stats["whitelisted_filtered"] += 1
                return

            # Track attempt
            self.attempts[src_ip].append((now, dst_port, dst_ip))
            self.scan_targets[dst_ip].add(src_ip)

            self._cleanup_old(src_ip, now)

            # Periodic cleanup
            self._cleanup_inactive_ips(now)

            # Compute stats in window
            attempts_in_window = list(self.attempts[src_ip])
            ports_in_window = [p for (_, p, _) in attempts_in_window]
            dst_ips_in_window = list(set([d for (_, _, d) in attempts_in_window]))

            unique_ports_set = set(ports_in_window)
            unique_ports = len(unique_ports_set)
            total_attempts = len(attempts_in_window)

            # Calculate scan rate (attempts per second)
            scan_rate = total_attempts / self.window_seconds if self.window_seconds > 0 else 0

            # Cooldown check
            if self._in_cooldown(src_ip, now):
                return

            # Detection rules
            reason = None
            is_sequential = False

            if unique_ports >= self.unique_port_threshold:
                reason = f"Many unique ports ({unique_ports}) in {self.window_seconds}s"
            elif self._has_sequential_run(unique_ports_set, self.sequential_threshold):
                reason = f"Sequential scan pattern detected (run >= {self.sequential_threshold})"
                is_sequential = True

            # Additional detection: Rapid scanning
            if scan_rate > 10:  # More than 10 attempts per second
                reason = reason or f"Rapid scanning detected ({scan_rate:.1f} attempts/sec)"

            if reason:
                severity = self._determine_severity(unique_ports, is_sequential, scan_rate)
                sample = sorted(unique_ports_set)[:40]

                alert = Alert(
                    ts=now,
                    timestamp=datetime.fromtimestamp(now).isoformat(),
                    src_ip=src_ip,
                    unique_ports=unique_ports,
                    window_seconds=self.window_seconds,
                    reason=reason,
                    severity=severity,
                    sample_ports=sample,
                    dst_ips=dst_ips_in_window[:10],
                    total_attempts=total_attempts,
                )

                self.last_alert[src_ip] = now
                self._emit_alert(alert)

        except Exception as e:
            print(f"[!] Error processing packet: {e}", file=sys.stderr)

    def print_stats(self) -> None:
        """Print detection statistics."""
        print("\n[*] Detection Statistics:")
        print(f"    Packets processed: {self.stats['packets_processed']}")
        print(f"    Alerts generated: {self.stats['alerts_generated']}")
        print(f"    Whitelisted filtered: {self.stats['whitelisted_filtered']}")
        print(f"    Active tracked IPs: {len(self.attempts)}")

    def run(self, iface: Optional[str] = None) -> None:
        """Start packet sniffing and detection."""
        # Check root privileges
        if os.name != 'nt' and os.geteuid() != 0:
            print(
                "[!] This tool requires root/sudo privileges for packet capture.",
                file=sys.stderr,
            )
            print("[!] Run with: sudo python3 port_scan_detector.py", file=sys.stderr)
            sys.exit(1)

        # Disable Scapy verbose output
        conf.verb = 0

        print("[*] Enhanced Port Scan Detection Tool started")
        print(f"[*] Interface: {iface or 'default'}")
        print(f"[*] BPF filter: {self.bpf_filter}")
        print(f"[*] Unique port threshold: {self.unique_port_threshold}")
        print(f"[*] Sequential threshold: {self.sequential_threshold}")
        print(f"[*] Window: {self.window_seconds}s")
        print(f"[*] Whitelisted IPs: {len(self.whitelist_ips)}")
        if self.log_file:
            print(f"[*] Logging to: {self.log_file}")
        print("[*] Press Ctrl+C to stop\n")

        try:
            sniff(
                iface=iface,
                filter=self.bpf_filter,
                prn=self.process_packet,
                store=False,
            )
        except KeyboardInterrupt:
            print("\n[*] Stopping detector...")
            self.print_stats()
        except PermissionError:
            print(
                "[!] Permission denied. Ensure you have CAP_NET_RAW capability.",
                file=sys.stderr,
            )
            sys.exit(1)
        except Exception as e:
            print(f"[!] Fatal error: {e}", file=sys.stderr)
            self.print_stats()
            raise


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    p = argparse.ArgumentParser(
        description="Enhanced Port Scan Detection Tool (SYN-based) with Scapy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 port_scan_detector.py -i eth0
  sudo python3 port_scan_detector.py --window 15 --unique-threshold 25
  sudo python3 port_scan_detector.py --whitelist 192.168.1.100,10.0.0.5
        """,
    )

    p.add_argument(
        "-i", "--iface",
        help="Network interface (e.g., eth0, wlan0). If omitted, uses default."
    )
    p.add_argument(
        "--window", type=int, default=10,
        help="Sliding window in seconds (default: 10)"
    )
    p.add_argument(
        "--unique-threshold", type=int, default=20,
        help="Unique ports in window to trigger alert (default: 20)"
    )
    p.add_argument(
        "--sequential-threshold", type=int, default=10,
        help="Sequential run length to trigger alert (default: 10)"
    )
    p.add_argument(
        "--cooldown", type=int, default=30,
        help="Cooldown in seconds per source IP (default: 30)"
    )
    p.add_argument(
        "--log", default="logs/alerts.jsonl",
        help="JSONL log file path (default: logs/alerts.jsonl, empty to disable)"
    )
    p.add_argument(
        "--exec", dest="exec_cmd", default="",
        help="Command to execute on alert (optional)"
    )
    p.add_argument(
        "--filter", default="tcp",
        help='BPF filter for sniffing (default: "tcp")'
    )
    p.add_argument(
        "--whitelist", default="",
        help="Comma-separated list of IPs to whitelist (e.g., 192.168.1.1,10.0.0.1)"
    )
    p.add_argument(
        "--cleanup-interval", type=int, default=300,
        help="Interval for memory cleanup in seconds (default: 300)"
    )
    p.add_argument(
        "--max-inactive", type=int, default=600,
        help="Max inactive time before IP cleanup in seconds (default: 600)"
    )

    return p.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_args()

    log_file = args.log.strip() or None
    exec_cmd = args.exec_cmd.strip() or None

    # Parse whitelist
    whitelist_ips = set()
    if args.whitelist.strip():
        whitelist_ips = set(ip.strip() for ip in args.whitelist.split(",") if ip.strip())
        print(f"[*] Loaded {len(whitelist_ips)} whitelisted IPs")

    detector = PortScanDetector(
        window_seconds=args.window,
        unique_port_threshold=args.unique_threshold,
        sequential_threshold=args.sequential_threshold,
        cooldown_seconds=args.cooldown,
        log_file=log_file,
        exec_cmd=exec_cmd,
        bpf_filter=args.filter,
        whitelist_ips=whitelist_ips,
        cleanup_interval=args.cleanup_interval,
        max_inactive_time=args.max_inactive,
    )

    detector.run(iface=args.iface)


if __name__ == "__main__":
    main()
