"""Sonuçları IPv4 ve IPv6 olarak ayrı dosyalara kaydeder. Rollback korumalı."""

import json
import logging
import os
from typing import Dict

from config import IPV4_FILE, IPV6_FILE, OUTPUT_JSON, OUTPUT_DIR, MIN_SUCCESS_RATIO

logger = logging.getLogger(__name__)


def _write_ip_file(filepath: str, results: Dict, version: str):
    """Belirtilen IP versiyonu için dosya yazar."""
    data = results[version]
    ips = data["ips"]
    cidrs = data["cidrs"]

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"# {version.upper()} Blacklist\n")
        f.write(f"# Updated: {results['timestamp']}\n")
        f.write(f"# IPs: {len(ips)} | CIDRs: {len(cidrs)}\n")
        f.write(f"# Duration: {results['elapsed_seconds']}s\n")
        f.write(f"# Sources: {results['successful_sources']}/{results['total_sources']} OK\n")
        f.write("#\n")
        for ip in ips:
            f.write(f"{ip}\n")
        if cidrs:
            f.write("#\n# === CIDR ===\n")
            for cidr in cidrs:
                f.write(f"{cidr}\n")

    logger.info(f"Kaydedildi: {filepath} ({len(ips)} IP, {len(cidrs)} CIDR)")


def save_results(results: Dict) -> bool:
    """Sonuçları dosyalara kaydeder. Rollback koruması uygular.

    Returns:
        True: dosyalar yazıldı
        False: yetersiz veri, mevcut dosyalar korundu
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    total = results.get("total_sources", 1)
    success = results.get("successful_sources", 0)
    ratio = success / total if total > 0 else 0

    # Rollback koruması: yeterli kaynak başarılı değilse dosyaları güncelleme
    if success == 0:
        logger.critical(
            "TUM KAYNAKLAR BASARISIZ! Mevcut cikti dosyalari korunuyor."
        )
        return False

    if ratio < MIN_SUCCESS_RATIO:
        logger.critical(
            f"Basari orani cok dusuk: {success}/{total} ({ratio:.0%}). "
            f"Esik: {MIN_SUCCESS_RATIO:.0%}. Mevcut dosyalar korunuyor."
        )
        return False

    _write_ip_file(IPV4_FILE, results, "ipv4")
    _write_ip_file(IPV6_FILE, results, "ipv6")

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    logger.info(f"JSON kaydedildi: {OUTPUT_JSON}")

    return True


def print_summary(results: Dict):
    """Ozet raporu yazdirir."""
    ipv4_total = len(results["ipv4"]["ips"]) + len(results["ipv4"]["cidrs"])
    ipv6_total = len(results["ipv6"]["ips"]) + len(results["ipv6"]["cidrs"])
    fail_count = len(results.get("failures", {}))

    print(f"\n{'=' * 60}")
    print(f"  IP BLACKLIST AGGREGATOR - OZET RAPOR")
    print(f"{'=' * 60}")
    print(f"  Zaman       : {results['timestamp']}")
    print(f"  Sure        : {results['elapsed_seconds']} saniye")
    print(f"  Kaynaklar   : {results['successful_sources']}/{results['total_sources']} basarili")
    if fail_count > 0:
        print(f"  HATALAR     : {fail_count} kaynak basarisiz!")
    print(f"  IPv4        : {len(results['ipv4']['ips']):,} IP + {len(results['ipv4']['cidrs']):,} CIDR")
    print(f"  IPv6        : {len(results['ipv6']['ips']):,} IP + {len(results['ipv6']['cidrs']):,} CIDR")
    print(f"  Toplam      : {ipv4_total + ipv6_total:,}")
    print(f"{'=' * 60}")
    print(f"  KAYNAKLAR:")
    print(f"  {'-' * 56}")
    for src, count in sorted(results["sources"].items(), key=lambda x: -x[1]):
        if src in results.get("failures", {}):
            status = "X"
        elif count > 0:
            status = "+"
        else:
            status = "?"
        print(f"  {status} {src:<40} {count:>8,}")
    print(f"{'=' * 60}")

    if results.get("failures"):
        print(f"  HATA DETAYLARI:")
        print(f"  {'-' * 56}")
        for src, err in results["failures"].items():
            print(f"  ! {src}: {err[:80]}")
        print(f"{'=' * 60}")

    print(f"  Dosyalar:")
    print(f"    IPv4   : output/ipv4_blacklist.txt")
    print(f"    IPv6   : output/ipv6_blacklist.txt")
    print(f"    JSON   : output/blacklist_full.json")
    print(f"    Saglik : output/health_report.md")
    print(f"{'=' * 60}\n")
