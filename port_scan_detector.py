# version 2 updated by ADITYA UPMANYU 
#!/usr/bin/env python3
"""
Enhanced Port Scan Detection Tool using Scapy
Version: 2.1.0

Detects:
- Multiple ports accessed by the same source IP within a sliding time window
- Sequential scanning behavior (e.g., 20,21,22,23...)
- Distributed scans from multiple sources
- Various scan patterns (aggressive vs. slow scans)

Enhancements over v1:
- Root privilege validation
- Memory management and cleanup
- IP whitelisting
- Severity levels
- Destination IP tracking
- Better error handling
- Performance optimizations
- Named constants for magic numbers
- Improved type annotations
- Refined alert rate calculation
- Structured startup banner
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
from typing import Deque, Dict, List, Optional, Set, Tuple
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, conf  # type: ignore
except ImportError:
    print("[!] Scapy not found. Install with: pip install scapy", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# TCP flag constants
# ---------------------------------------------------------------------------
TCP_FLAG_SYN: int = 0x02
TCP_FLAG_ACK: int = 0x10

# ---------------------------------------------------------------------------
# Severity thresholds
# ---------------------------------------------------------------------------
SEVERITY_CRITICAL_PORTS: int = 50
SEVERITY_CRITICAL_RATE: float = 20.0
SEVERITY_HIGH_PORTS: int = 30
SEVERITY_MEDIUM_PORTS: int = 20
RAPID_SCAN_RATE_THRESHOLD: float = 10.0  # attempts/sec before "rapid" flag triggers

# ---------------------------------------------------------------------------
# Default configuration values
# ---------------------------------------------------------------------------
DEFAULT_WINDOW_SECONDS: int = 10
DEFAULT_UNIQUE_PORT_THRESHOLD: int = 20
DEFAULT_SEQUENTIAL_THRESHOLD: int = 10
DEFAULT_COOLDOWN_SECONDS: int = 30
DEFAULT_LOG_FILE: str = "logs/alerts.jsonl"
DEFAULT_BPF_FILTER: str = "tcp"
DEFAULT_CLEANUP_INTERVAL: int = 300
DEFAULT_MAX_INACTIVE_TIME: int = 600
MAX_SAMPLE_PORTS: int = 40
MAX_DST_IPS_IN_ALERT: int = 10
MAX_PORTS_PRINTED_IN_CONSOLE: int = 10


@dataclass
class Alert:
    """Represents a single port-scan detection alert."""

    ts: float
    timestamp: str
    src_ip: str
    unique_ports: int
    window_seconds: int
    reason: str
    severity: str
    sample_ports: List[int]
    dst_ips: List[str]
    total_attempts: int


class PortScanDetector:
    """
    Stateful port-scan detector that processes raw TCP/IP packets.

    The detector maintains a sliding window of SYN packets per source IP
    and fires alerts when configurable heuristics are exceeded:

    1. **Unique-port threshold** – more than ``unique_port_threshold`` distinct
       destination ports contacted within ``window_seconds``.
    2. **Sequential pattern** – a run of ``sequential_threshold`` or more
       consecutive port numbers in the window.
    3. **Rapid scanning** – more than ``RAPID_SCAN_RATE_THRESHOLD`` SYN
       packets per second from one source.

    Alerts are suppressed per source IP for ``cooldown_seconds`` after the
    first alert to avoid log spam.
    """
# MUSKAN RAWAT INTIALISIZE IT 
    def __init__(
        self,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        unique_port_threshold: int = DEFAULT_UNIQUE_PORT_THRESHOLD,
        sequential_threshold: int = DEFAULT_SEQUENTIAL_THRESHOLD,
        cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS,
        log_file: Optional[str] = None,
        exec_cmd: Optional[str] = None,
        bpf_filter: str = DEFAULT_BPF_FILTER,
        whitelist_ips: Optional[Set[str]] = None,
        cleanup_interval: int = DEFAULT_CLEANUP_INTERVAL,
        max_inactive_time: int = DEFAULT_MAX_INACTIVE_TIME,
    ) -> None:
        self.window_seconds = window_seconds
        self.unique_port_threshold = unique_port_threshold
        self.sequential_threshold = sequential_threshold
        self.cooldown_seconds = cooldown_seconds
        self.log_file = log_file
        self.exec_cmd = exec_cmd
        self.bpf_filter = bpf_filter
        self.whitelist_ips: Set[str] = whitelist_ips or set()
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

        # Runtime statistics
        self.stats: Dict[str, int] = {
            "packets_processed": 0,
            "alerts_generated": 0,
            "whitelisted_filtered": 0,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _cleanup_old(self, src_ip: str, now: float) -> None:
        """Remove entries outside the sliding window for a specific IP."""
        dq = self.attempts[src_ip]
        while dq and (now - dq[0][0]) > self.window_seconds:
            dq.popleft()

    def _cleanup_inactive_ips(self, now: float) -> None:
        """
        Periodically evict inactive source IPs to prevent unbounded memory growth.

        An IP is considered inactive when its most-recent recorded attempt is
        older than ``max_inactive_time`` seconds, or its deque is empty.
        """
        if (now - self.last_cleanup) < self.cleanup_interval:
            return

        inactive_ips = [
            ip
            for ip, dq in self.attempts.items()
            if not dq or (now - dq[-1][0]) > self.max_inactive_time
        ]

        for ip in inactive_ips:
            del self.attempts[ip]
            self.last_alert.pop(ip, None)

        # Cleanup empty scan-target entries
        empty_targets = [dst for dst, srcs in self.scan_targets.items() if not srcs]
        for dst in empty_targets:
            del self.scan_targets[dst]

        self.last_cleanup = now
        if inactive_ips:
            print(f"[*] Cleaned up {len(inactive_ips)} inactive IPs")

    @staticmethod
    def _is_syn_only(tcp_flags: int) -> bool:
        """Return *True* if the packet carries SYN but not ACK (new connection attempt)."""
        return bool(tcp_flags & TCP_FLAG_SYN) and not bool(tcp_flags & TCP_FLAG_ACK)

    @staticmethod
    def _has_sequential_run(ports: Set[int], min_len: int) -> bool:
        """
        Detect a sequential port-scanning pattern.

        Returns *True* when ``ports`` contains a run of at least ``min_len``
        consecutive integers (e.g., {20, 21, 22, 23} with ``min_len=4``).
        """
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
        """Return *True* when the source IP is still within the alert cooldown period."""
        last = self.last_alert.get(src_ip)
        return last is not None and (now - last) < self.cooldown_seconds

    def _determine_severity(
        self, unique_ports: int, is_sequential: bool, scan_rate: float
    ) -> str:
        """
        Map scan characteristics to a severity label.

        +----------+---------------------------------------------------------+
        | Severity | Condition                                               |
        +==========+=========================================================+
        | CRITICAL | ≥50 unique ports **or** scan rate > 20 attempts/sec    |
        +----------+---------------------------------------------------------+
        | HIGH     | ≥30 unique ports **or** sequential pattern detected     |
        +----------+---------------------------------------------------------+
        | MEDIUM   | ≥20 unique ports                                        |
        +----------+---------------------------------------------------------+
        | LOW      | all other triggered conditions                          |
        +----------+---------------------------------------------------------+
        """
        if unique_ports >= SEVERITY_CRITICAL_PORTS or scan_rate > SEVERITY_CRITICAL_RATE:
            return "CRITICAL"
        if unique_ports >= SEVERITY_HIGH_PORTS or is_sequential:
            return "HIGH"
        if unique_ports >= SEVERITY_MEDIUM_PORTS:
            return "MEDIUM"
        return "LOW"

    # ------------------------------------------------------------------
    # Alert emission
    # ------------------------------------------------------------------

    def _emit_alert(self, alert: Alert) -> None:
        """
        Dispatch a security alert to all configured sinks.

        Sinks:
        - **stdout** – colour-coded one-liner.
        - **JSONL log file** – append-only, one JSON object per line.
        - **exec hook** – optional shell command with alert details exported
          as environment variables (``PSD_*``).
        """
        severity_colors: Dict[str, str] = {
            "CRITICAL": "\033[91m",  # bright red
            "HIGH":     "\033[93m",  # yellow
            "MEDIUM":   "\033[94m",  # blue
            "LOW":      "\033[92m",  # green
        }
        reset = "\033[0m"
        color = severity_colors.get(alert.severity, "")

        print(
            f"{color}[ALERT-{alert.severity}]{reset} "
            f"src={alert.src_ip} "
            f"unique_ports={alert.unique_ports} "
            f"attempts={alert.total_attempts} "
            f"window={alert.window_seconds}s "
            f"reason={alert.reason} "
            f"sample_ports={alert.sample_ports[:MAX_PORTS_PRINTED_IN_CONSOLE]}"
        )

        # JSONL log
        if self.log_file:
            try:
                os.makedirs(os.path.dirname(self.log_file) or ".", exist_ok=True)
                with open(self.log_file, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(asdict(alert), ensure_ascii=False) + "\n")
            except OSError as exc:
                print(f"[!] Failed to write to log file: {exc}", file=sys.stderr)

        # Optional shell hook
        if self.exec_cmd:
            env = os.environ.copy()
            env.update(
                {
                    "PSD_SRC_IP":       alert.src_ip,
                    "PSD_UNIQUE_PORTS": str(alert.unique_ports),
                    "PSD_REASON":       alert.reason,
                    "PSD_SEVERITY":     alert.severity,
                    "PSD_SAMPLE_PORTS": ",".join(map(str, alert.sample_ports)),
                    "PSD_TIMESTAMP":    alert.timestamp,
                }
            )
            try:
                subprocess.Popen(
                    self.exec_cmd,
                    shell=True,
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception as exc:  # noqa: BLE001
                print(f"[!] Failed to execute command hook: {exc}", file=sys.stderr)

        self.stats["alerts_generated"] += 1

    # ------------------------------------------------------------------
    # Packet processing
    # ------------------------------------------------------------------

    def process_packet(self, pkt) -> None:
        """
        Callback invoked by Scapy for every captured packet.

        Only SYN-only TCP packets that carry an IP layer are analysed.
        All other packets are silently discarded.
        """
        try:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return

            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]

            # Only consider SYN packets (new connection attempts)
            if not self._is_syn_only(int(tcp_layer.flags)):
                return

            now = time.time()
            src_ip: str = ip_layer.src
            dst_ip: str = ip_layer.dst
            dst_port: int = int(tcp_layer.dport)

            self.stats["packets_processed"] += 1

            # Whitelist check – skip trusted sources
            if src_ip in self.whitelist_ips:
                self.stats["whitelisted_filtered"] += 1
                return

            # Record attempt and update target map
            self.attempts[src_ip].append((now, dst_port, dst_ip))
            self.scan_targets[dst_ip].add(src_ip)

            # Expire old entries for this source
            self._cleanup_old(src_ip, now)

            # Periodic global memory cleanup
            self._cleanup_inactive_ips(now)

            # Aggregate window stats
            window_entries = list(self.attempts[src_ip])
            ports_in_window: List[int] = [p for (_, p, _) in window_entries]
            dst_ips_in_window: List[str] = list({d for (_, _, d) in window_entries})

            unique_ports_set: Set[int] = set(ports_in_window)
            unique_ports: int = len(unique_ports_set)
            total_attempts: int = len(window_entries)
            scan_rate: float = (
                total_attempts / self.window_seconds if self.window_seconds > 0 else 0.0
            )

            # Respect per-IP cooldown to avoid alert spam
            if self._in_cooldown(src_ip, now):
                return

            # ---- Detection rules ----------------------------------------
            reason: Optional[str] = None
            is_sequential: bool = False

            if unique_ports >= self.unique_port_threshold:
                reason = (
                    f"Many unique ports ({unique_ports}) within {self.window_seconds}s window"
                )
            elif self._has_sequential_run(unique_ports_set, self.sequential_threshold):
                reason = (
                    f"Sequential scan pattern detected (run ≥ {self.sequential_threshold})"
                )
                is_sequential = True

            # Rapid-fire scanning is an independent trigger
            if scan_rate > RAPID_SCAN_RATE_THRESHOLD:
                reason = reason or (
                    f"Rapid scanning detected ({scan_rate:.1f} attempts/sec)"
                )
            # ---- End detection rules ------------------------------------

            if reason:
                severity = self._determine_severity(unique_ports, is_sequential, scan_rate)
                sample_ports = sorted(unique_ports_set)[:MAX_SAMPLE_PORTS]

                alert = Alert(
                    ts=now,
                    timestamp=datetime.fromtimestamp(now).isoformat(),
                    src_ip=src_ip,
                    unique_ports=unique_ports,
                    window_seconds=self.window_seconds,
                    reason=reason,
                    severity=severity,
                    sample_ports=sample_ports,
                    dst_ips=dst_ips_in_window[:MAX_DST_IPS_IN_ALERT],
                    total_attempts=total_attempts,
                )

                self.last_alert[src_ip] = now
                self._emit_alert(alert)

        except Exception as exc:  # noqa: BLE001
            print(f"[!] Error processing packet: {exc}", file=sys.stderr)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def print_stats(self) -> None:
        """Print a summary of runtime detection statistics to stdout."""
        print("\n[*] Detection Statistics:")
        print(f"    Packets processed  : {self.stats['packets_processed']}")
        print(f"    Alerts generated   : {self.stats['alerts_generated']}")
        print(f"    Whitelisted skipped: {self.stats['whitelisted_filtered']}")
        print(f"    Active tracked IPs : {len(self.attempts)}")

    def _print_banner(self, iface: Optional[str]) -> None:
        """Print startup information banner."""
        sep = "-" * 52
        print(sep)
        print("  Enhanced Port Scan Detection Tool  v2.1.0")
        print(sep)
        print(f"  Interface         : {iface or 'default'}")
        print(f"  BPF filter        : {self.bpf_filter}")
        print(f"  Unique port thr.  : {self.unique_port_threshold}")
        print(f"  Sequential thr.   : {self.sequential_threshold}")
        print(f"  Time window       : {self.window_seconds}s")
        print(f"  Alert cooldown    : {self.cooldown_seconds}s")
        print(f"  Whitelisted IPs   : {len(self.whitelist_ips)}")
        if self.log_file:
            print(f"  Log file          : {self.log_file}")
        if self.exec_cmd:
            print(f"  Exec hook         : {self.exec_cmd}")
        print(sep)
        print("  Press Ctrl+C to stop\n")

    def run(self, iface: Optional[str] = None) -> None:
        """
        Start packet sniffing and begin detection.

        Requires ``CAP_NET_RAW`` (or root on Linux/macOS).  On Windows the
        privilege check is skipped – Scapy itself will raise an appropriate
        error if permissions are insufficient.
        """
        if os.name != "nt" and os.geteuid() != 0:
            print(
                "[!] Root/sudo privileges are required for packet capture.",
                file=sys.stderr,
            )
            print("[!] Run with: sudo python3 port_scan_detector.py", file=sys.stderr)
            sys.exit(1)

        conf.verb = 0  # Suppress Scapy verbose output

        self._print_banner(iface)

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
                "[!] Permission denied – ensure the process has CAP_NET_RAW capability.",
                file=sys.stderr,
            )
            sys.exit(1)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Fatal error: {exc}", file=sys.stderr)
            self.print_stats()
            raise


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Enhanced Port Scan Detection Tool (SYN-based) using Scapy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 port_scan_detector.py -i eth0
  sudo python3 port_scan_detector.py --window 15 --unique-threshold 25
  sudo python3 port_scan_detector.py --whitelist 192.168.1.100,10.0.0.5
  sudo python3 port_scan_detector.py --log /var/log/psd/alerts.jsonl --exec "notify.sh"
        """,
    )

    parser.add_argument(
        "-i", "--iface",
        metavar="INTERFACE",
        help="Network interface to capture on (e.g. eth0, wlan0). "
             "Omit to use the system default.",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=DEFAULT_WINDOW_SECONDS,
        metavar="SECONDS",
        help=f"Sliding detection window in seconds (default: {DEFAULT_WINDOW_SECONDS})",
    )
    parser.add_argument(
        "--unique-threshold",
        type=int,
        default=DEFAULT_UNIQUE_PORT_THRESHOLD,
        metavar="N",
        help=(
            f"Number of unique destination ports within the window that triggers "
            f"an alert (default: {DEFAULT_UNIQUE_PORT_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--sequential-threshold",
        type=int,
        default=DEFAULT_SEQUENTIAL_THRESHOLD,
        metavar="N",
        help=(
            f"Minimum consecutive-port run length that triggers a sequential-scan "
            f"alert (default: {DEFAULT_SEQUENTIAL_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--cooldown",
        type=int,
        default=DEFAULT_COOLDOWN_SECONDS,
        metavar="SECONDS",
        help=(
            f"Per-source-IP alert cooldown in seconds to suppress duplicate alerts "
            f"(default: {DEFAULT_COOLDOWN_SECONDS})"
        ),
    )
    parser.add_argument(
        "--log",
        default=DEFAULT_LOG_FILE,
        metavar="PATH",
        help=(
            f"Path to the JSONL alert log file. Pass an empty string to disable "
            f"file logging (default: {DEFAULT_LOG_FILE})"
        ),
    )
    parser.add_argument(
        "--exec",
        dest="exec_cmd",
        default="",
        metavar="CMD",
        help="Shell command to execute on each alert. Alert details are passed "
             "via PSD_* environment variables.",
    )
    parser.add_argument(
        "--filter",
        default=DEFAULT_BPF_FILTER,
        metavar="BPF",
        help=f'Berkeley Packet Filter expression (default: "{DEFAULT_BPF_FILTER}")',
    )
    parser.add_argument(
        "--whitelist",
        default="",
        metavar="IP[,IP...]",
        help="Comma-separated list of source IPs to ignore (e.g. 192.168.1.1,10.0.0.1)",
    )
    parser.add_argument(
        "--cleanup-interval",
        type=int,
        default=DEFAULT_CLEANUP_INTERVAL,
        metavar="SECONDS",
        help=(
            f"How often (in seconds) inactive IPs are evicted from memory "
            f"(default: {DEFAULT_CLEANUP_INTERVAL})"
        ),
    )
    parser.add_argument(
        "--max-inactive",
        type=int,
        default=DEFAULT_MAX_INACTIVE_TIME,
        metavar="SECONDS",
        help=(
            f"Maximum idle time (in seconds) before an IP is considered inactive "
            f"and removed (default: {DEFAULT_MAX_INACTIVE_TIME})"
        ),
    )

    return parser.parse_args()


def main() -> None:
    """Entry point – parse arguments and start the detector."""
    args = parse_args()

    log_file: Optional[str] = args.log.strip() or None
    exec_cmd: Optional[str] = args.exec_cmd.strip() or None

    whitelist_ips: Set[str] = set()
    if args.whitelist.strip():
        whitelist_ips = {ip.strip() for ip in args.whitelist.split(",") if ip.strip()}
        print(f"[*] Loaded {len(whitelist_ips)} whitelisted IP(s)")

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
