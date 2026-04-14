"""Raw text output — one IP/CIDR per line, no headers. Firewall-ready."""

from __future__ import annotations

import os

from threat_intel.domain.entities import CollectionResult
from threat_intel.domain.ports import OutputWriter


class RawIPv4Writer(OutputWriter):
    """Writes hourlyIPv4.txt — bare IPs + CIDRs, one per line."""

    @property
    def format_name(self) -> str:
        return "Raw IPv4"

    def write(self, result: CollectionResult, output_dir: str) -> str:
        path = os.path.join(output_dir, "hourlyIPv4.txt")
        os.makedirs(output_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for ip in result.ipv4_ips:
                f.write(f"{ip}\n")
            for cidr in result.ipv4_cidrs:
                f.write(f"{cidr}\n")
        return path


class AnnotatedIPv4Writer(OutputWriter):
    """Writes ipv4_blacklist.txt — IPs with metadata header."""

    @property
    def format_name(self) -> str:
        return "Annotated IPv4"

    def write(self, result: CollectionResult, output_dir: str) -> str:
        path = os.path.join(output_dir, "ipv4_blacklist.txt")
        os.makedirs(output_dir, exist_ok=True)
        ips = result.ipv4_ips
        cidrs = result.ipv4_cidrs
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# IPv4 Blacklist\n")
            f.write(f"# Updated: {result.timestamp.isoformat()}\n")
            f.write(f"# IPs: {len(ips)} | CIDRs: {len(cidrs)}\n")
            f.write(f"# Duration: {result.elapsed_seconds}s\n")
            f.write(f"# Sources: {result.successful_sources}/{result.total_sources} OK\n")
            if result.whitelist_filtered_count > 0:
                f.write(f"# Whitelist filtered: {result.whitelist_filtered_count}\n")
            f.write("#\n")
            for ip in ips:
                f.write(f"{ip}\n")
            if cidrs:
                f.write("#\n# === CIDR ===\n")
                for cidr in cidrs:
                    f.write(f"{cidr}\n")
        return path


class AnnotatedIPv6Writer(OutputWriter):
    """Writes ipv6_blacklist.txt — IPv6 addresses with metadata header."""

    @property
    def format_name(self) -> str:
        return "Annotated IPv6"

    def write(self, result: CollectionResult, output_dir: str) -> str:
        path = os.path.join(output_dir, "ipv6_blacklist.txt")
        os.makedirs(output_dir, exist_ok=True)
        ips = result.ipv6_ips
        cidrs = result.ipv6_cidrs
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# IPv6 Blacklist\n")
            f.write(f"# Updated: {result.timestamp.isoformat()}\n")
            f.write(f"# IPs: {len(ips)} | CIDRs: {len(cidrs)}\n")
            f.write(f"# Duration: {result.elapsed_seconds}s\n")
            f.write(f"# Sources: {result.successful_sources}/{result.total_sources} OK\n")
            f.write("#\n")
            for ip in ips:
                f.write(f"{ip}\n")
            if cidrs:
                f.write("#\n# === CIDR ===\n")
                for cidr in cidrs:
                    f.write(f"{cidr}\n")
        return path
