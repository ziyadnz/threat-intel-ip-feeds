"""Saglik raporu olusturucu - Markdown formatinda."""

import logging
import os
from datetime import datetime, timezone
from typing import Dict

from config import HEALTH_REPORT, OUTPUT_DIR
from health_tracker import load_health, get_stale_sources, get_failing_sources

logger = logging.getLogger(__name__)


def generate_report(results: Dict) -> str:
    """Saglik raporunu olusturur ve dosyaya yazar. Rapor metnini doner."""
    health = load_health()
    stale = get_stale_sources(health)
    failing = get_failing_sources(health)
    failures = results.get("failures", {})

    lines = []
    lines.append(f"# IP Blacklist Aggregator - Saglik Raporu")
    lines.append(f"")
    lines.append(f"**Tarih:** {results['timestamp']}")
    lines.append(f"**Sure:** {results['elapsed_seconds']} saniye")
    lines.append(f"**Basarili:** {results['successful_sources']}/{results['total_sources']}")
    lines.append(f"")

    # Bu calisma hatalari
    if failures:
        lines.append(f"## Bu Calismada Basarisiz Kaynaklar")
        lines.append(f"")
        lines.append(f"| Kaynak | Hata |")
        lines.append(f"|--------|------|")
        for src, err in failures.items():
            lines.append(f"| {src} | {err[:100]} |")
        lines.append(f"")

    # Stale kaynaklar
    if stale:
        lines.append(f"## {len(stale)} Kaynak 30+ Gundur Veri Donmuyor")
        lines.append(f"")
        lines.append(f"| Kaynak | Son Basari | Gun | Ardisik Hata |")
        lines.append(f"|--------|-----------|-----|-------------|")
        for s in stale:
            lines.append(f"| {s['source']} | {s['last_success']} | {s['days_since']} | {s['consecutive_failures']} |")
        lines.append(f"")

    # Ardisik hata olan kaynaklar
    if failing:
        lines.append(f"## Ardisik Hata Veren Kaynaklar")
        lines.append(f"")
        lines.append(f"| Kaynak | Ardisik Hata | Son Hata | Sebep |")
        lines.append(f"|--------|-------------|----------|-------|")
        for f_item in failing:
            lines.append(f"| {f_item['source']} | {f_item['consecutive_failures']} | "
                         f"{f_item['last_failure']} | {f_item['reason'][:60]} |")
        lines.append(f"")

    # Kaynak detay tablosu
    lines.append(f"## Tum Kaynaklar")
    lines.append(f"")
    lines.append(f"| Kaynak | IP Sayisi | Durum |")
    lines.append(f"|--------|----------|-------|")
    for src, count in sorted(results["sources"].items(), key=lambda x: -x[1]):
        if src in failures:
            status = "HATA"
        elif count > 0:
            status = "OK"
        else:
            status = "BOS"
        lines.append(f"| {src} | {count:,} | {status} |")
    lines.append(f"")

    # Hic sorun yoksa
    if not failures and not stale and not failing:
        lines.append(f"## Tum kaynaklar saglikli.")
        lines.append(f"")

    report_text = "\n".join(lines)

    # Dosyaya yaz
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    try:
        with open(HEALTH_REPORT, "w", encoding="utf-8") as fh:
            fh.write(report_text)
        logger.info(f"Saglik raporu yazildi: {HEALTH_REPORT}")
    except OSError as e:
        logger.error(f"Saglik raporu yazilamadi: {e}")

    return report_text


def should_notify(results: Dict) -> bool:
    """GitHub Issue acilmali mi? Hata veya stale kaynak varsa True."""
    if results.get("failures"):
        return True
    health = load_health()
    if get_stale_sources(health):
        return True
    if get_failing_sources(health):
        return True
    return False
