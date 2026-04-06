"""Ana toplama motoru: tüm kaynakları paralel çalıştırır, hata izolasyonu sağlar."""

import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict

from config import MAX_WORKERS
from utils import is_ipv6
from health_tracker import (
    load_health, save_health, record_success, record_failure, record_no_data,
)
from sources.global_sources import (
    fetch_spamhaus_drop, fetch_spamhaus_dropv6,
    fetch_feodo_tracker,
    fetch_dshield, fetch_blocklist_de,
    fetch_cins_army, fetch_emerging_threats,
    fetch_binarydefense, fetch_greensnow,
    fetch_tor_exit_nodes, fetch_stamparm_ipsum,
)
from sources.turkey_sources import fetch_usom, fetch_rtbh
from sources.api_sources import fetch_abuseipdb, fetch_alienvault_otx

logger = logging.getLogger(__name__)

# Kaynak registry - her kaynağın sabit bir adı var
SOURCE_REGISTRY = [
    ("Spamhaus DROP",               fetch_spamhaus_drop),
    ("Spamhaus DROPv6",             fetch_spamhaus_dropv6),
    ("Feodo Tracker",               fetch_feodo_tracker),
    ("DShield",                     fetch_dshield),
    ("Blocklist.de (all)",          lambda: fetch_blocklist_de("all")),
    ("Blocklist.de (ssh)",          lambda: fetch_blocklist_de("ssh")),
    ("Blocklist.de (mail)",         lambda: fetch_blocklist_de("mail")),
    ("Blocklist.de (apache)",       lambda: fetch_blocklist_de("apache")),
    ("Blocklist.de (bots)",         lambda: fetch_blocklist_de("bots")),
    ("Blocklist.de (bruteforcelogin)", lambda: fetch_blocklist_de("bruteforcelogin")),
    ("Blocklist.de (strongips)",    lambda: fetch_blocklist_de("strongips")),
    ("CINS Army",                   fetch_cins_army),
    ("Emerging Threats",            fetch_emerging_threats),
    ("BinaryDefense",               fetch_binarydefense),
    ("GreenSnow",                   fetch_greensnow),
    ("Tor Exit Nodes",              fetch_tor_exit_nodes),
    ("Stamparm IPsum",              fetch_stamparm_ipsum),
    ("USOM (Turkiye)",              fetch_usom),
    ("RTBH (Turkiye)",              fetch_rtbh),
    ("AbuseIPDB",                   fetch_abuseipdb),
    ("AlienVault OTX",              fetch_alienvault_otx),
]


def _run_source(name, fetch_fn):
    """Tek bir kaynağı güvenli şekilde çalıştırır. Asla exception fırlatmaz."""
    try:
        ips, _ = fetch_fn()
        return name, ips, None  # (kaynak_adı, ip_set, hata)
    except Exception as e:
        # Detaylı hata mesajı: HTTP status kodu + URL varsa ekle
        error_type = type(e).__name__
        detail = str(e)
        if hasattr(e, 'response') and e.response is not None:
            status = e.response.status_code
            url = e.response.url
            error_msg = f"HTTP {status} | {url} | {error_type}: {detail}"
        else:
            error_msg = f"{error_type}: {detail}"
        logger.error(f"[{name}] {error_msg}", exc_info=True)
        return name, set(), error_msg


def collect_all() -> Dict:
    """Tüm kaynaklardan IP blacklist'leri paralel toplar, hata izolasyonlu."""
    ipv4_ips = set()
    ipv4_cidrs = set()
    ipv6_ips = set()
    ipv6_cidrs = set()
    source_stats = {}
    failures = {}
    successful_count = 0

    health = load_health()

    logger.info("=" * 60)
    logger.info(f"IP Blacklist Aggregator - {len(SOURCE_REGISTRY)} kaynak taranacak")
    logger.info("=" * 60)

    start_time = datetime.now(timezone.utc)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {
            executor.submit(_run_source, name, fn): name
            for name, fn in SOURCE_REGISTRY
        }

        for future in as_completed(future_map):
            reg_name = future_map[future]
            try:
                name, ips, error = future.result()
            except Exception as e:
                # _run_source asla exception fırlatmaz ama yine de güvende olalım
                logger.critical(f"[{reg_name}] Kritik executor hatası: {e}")
                record_failure(health, reg_name, str(e))
                failures[reg_name] = str(e)
                source_stats[reg_name] = 0
                continue

            source_stats[name] = len(ips)

            if error:
                record_failure(health, name, error)
                failures[name] = error
            elif len(ips) == 0:
                record_no_data(health, name)
            else:
                record_success(health, name, len(ips))
                successful_count += 1

            for ip in ips:
                if is_ipv6(ip):
                    if "/" in ip:
                        ipv6_cidrs.add(ip)
                    else:
                        ipv6_ips.add(ip)
                else:
                    if "/" in ip:
                        ipv4_cidrs.add(ip)
                    else:
                        ipv4_ips.add(ip)

    save_health(health)

    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "sources": source_stats,
        "failures": failures,
        "total_sources": len(SOURCE_REGISTRY),
        "successful_sources": successful_count,
        "ipv4": {"ips": sorted(ipv4_ips), "cidrs": sorted(ipv4_cidrs)},
        "ipv6": {"ips": sorted(ipv6_ips), "cidrs": sorted(ipv6_cidrs)},
    }
