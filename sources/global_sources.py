"""Global blacklist kaynakları (kayıt gerektirmeyen)."""

import logging
from typing import Set, Tuple

from utils import safe_request, extract_ips_from_text, IPV4_PATTERN, is_valid_public_ip
from config import IPSUM_MIN_SCORE

logger = logging.getLogger(__name__)


def fetch_spamhaus_drop() -> Tuple[Set[str], str]:
    """Spamhaus DROP listesi (CIDR)."""
    source = "Spamhaus DROP"
    ips = set()
    resp = safe_request("https://www.spamhaus.org/drop/drop.txt")
    for line in resp.text.splitlines():
        line = line.strip()
        if line and not line.startswith(";"):
            cidr = line.split(";")[0].strip()
            if "/" in cidr:
                ips.add(cidr)
    logger.info(f"[{source}] {len(ips)} CIDR aralığı")
    return ips, source


def fetch_spamhaus_dropv6() -> Tuple[Set[str], str]:
    """Spamhaus DROPv6 listesi."""
    source = "Spamhaus DROPv6"
    ips = set()
    resp = safe_request("https://www.spamhaus.org/drop/dropv6.txt")
    for line in resp.text.splitlines():
        line = line.strip()
        if line and not line.startswith(";"):
            cidr = line.split(";")[0].strip()
            if "/" in cidr:
                ips.add(cidr)
    logger.info(f"[{source}] {len(ips)} IPv6 CIDR aralığı")
    return ips, source


def fetch_feodo_tracker() -> Tuple[Set[str], str]:
    """Feodo Tracker (abuse.ch) botnet C2 IP'leri."""
    source = "Feodo Tracker"
    resp = safe_request("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt")
    ips = extract_ips_from_text(resp.text)
    logger.info(f"[{source}] {len(ips)} IP")
    return ips, source


def fetch_dshield() -> Tuple[Set[str], str]:
    """DShield/SANS ISC intel feed."""
    source = "DShield"
    ips = set()
    headers = {"User-Agent": "IP-Blacklist-Aggregator/2.0"}
    resp = safe_request("https://isc.sans.edu/api/intelfeed?json", headers=headers)
    data = resp.json()
    if isinstance(data, list):
        for entry in data:
            ip = entry.get("ip", "")
            if is_valid_public_ip(ip):
                ips.add(ip)
    logger.info(f"[{source}] {len(ips)} IP")
    return ips, source


def fetch_blocklist_de(service: str = "all") -> Tuple[Set[str], str]:
    """Blocklist.de listeleri."""
    source = f"Blocklist.de ({service})"
    resp = safe_request(f"https://lists.blocklist.de/lists/{service}.txt")
    ips = extract_ips_from_text(resp.text)
    logger.info(f"[{source}] {len(ips)} IP")
    return ips, source


def fetch_cins_army() -> Tuple[Set[str], str]:
    """CINS Army listesi."""
    source = "CINS Army"
    resp = safe_request("https://cinsscore.com/list/ci-badguys.txt")
    ips = extract_ips_from_text(resp.text)
    logger.info(f"[{source}] {len(ips)} IP")
    return ips, source


def fetch_emerging_threats() -> Tuple[Set[str], str]:
    """Emerging Threats compromised IP listesi."""
    source = "Emerging Threats"
    resp = safe_request("https://rules.emergingthreats.net/blockrules/compromised-ips.txt")
    ips = extract_ips_from_text(resp.text)
    logger.info(f"[{source}] {len(ips)} IP")
    return ips, source


def fetch_binarydefense() -> Tuple[Set[str], str]:
    """BinaryDefense Artillery ban listesi."""
    source = "BinaryDefense"
    ips = set()
    resp = safe_request("https://www.binarydefense.com/banlist.txt")
    for line in resp.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and is_valid_public_ip(line):
            ips.add(line)
    logger.info(f"[{source}] {len(ips)} IP")
    return ips, source


def fetch_greensnow() -> Tuple[Set[str], str]:
    """GreenSnow blocklist."""
    source = "GreenSnow"
    resp = safe_request("https://blocklist.greensnow.co/greensnow.txt")
    ips = extract_ips_from_text(resp.text)
    logger.info(f"[{source}] {len(ips)} IP")
    return ips, source


def fetch_tor_exit_nodes() -> Tuple[Set[str], str]:
    """Tor çıkış düğümleri."""
    source = "Tor Exit Nodes"
    resp = safe_request("https://check.torproject.org/torbulkexitlist")
    ips = extract_ips_from_text(resp.text)
    logger.info(f"[{source}] {len(ips)} IP")
    return ips, source


def fetch_stamparm_ipsum() -> Tuple[Set[str], str]:
    """Stamparm IPsum (30+ listeden agregasyon)."""
    source = "Stamparm IPsum"
    ips = set()
    resp = safe_request(
        "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        timeout=120
    )
    for line in resp.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split("\t")
            if len(parts) >= 2:
                try:
                    if int(parts[1]) >= IPSUM_MIN_SCORE and is_valid_public_ip(parts[0]):
                        ips.add(parts[0])
                except ValueError:
                    pass
    logger.info(f"[{source}] {len(ips)} IP (skor >= {IPSUM_MIN_SCORE})")
    return ips, source
