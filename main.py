#!/usr/bin/env python3
"""
IP Blacklist Aggregator v3.0 - Enterprise Edition
23 kaynaktan IP blacklist'leri toplayip IPv4/IPv6 olarak ayri dosyalara kaydeder.
Failsafe mekanizmasi, saglik takibi ve GitHub Issue bildirimi icerir.
"""

import logging
import sys

from config import LOG_FILE
from collector import collect_all
from output_writer import save_results, print_summary
from health_report import generate_report, should_notify
from notifier import notify_github, close_resolved_issues

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger(__name__)


def main():
    print(r"""
    +======================================================+
    |       IP BLACKLIST AGGREGATOR v3.0                    |
    |       Enterprise Threat Intelligence Collector        |
    |  21 kaynak | Failsafe | Health Tracking | Auto-notify |
    +======================================================+
    """)

    # 1. Veri topla (hicbir kaynak tum sistemi cokertemez)
    results = collect_all()

    # 2. Sonuclari kaydet (rollback korumali)
    wrote = save_results(results)

    # 3. Ozet yazdir
    print_summary(results)

    # 4. Saglik raporu olustur (her zaman, basarisiz da olsa)
    report = generate_report(results)

    # 5. GitHub bildirimi
    if should_notify(results):
        fail_count = len(results.get("failures", {}))
        title = f"Source Health Alert - {results['timestamp'][:10]}"
        if fail_count > 0:
            title = f"[{fail_count} HATA] {title}"
        notify_github(title, report)
    else:
        # Sorun kalmadiysa acik issue'lari kapat
        close_resolved_issues()

    # 6. Cikis kodu: CI/CD pipeline'a sinyal gonder
    if not wrote:
        logger.critical("Cikti dosyalari YAZILMADI. Cikis kodu: 2")
        sys.exit(2)

    if results.get("failures"):
        logger.warning(f"{len(results['failures'])} kaynak basarisiz, cikis kodu: 1")
        sys.exit(1)

    logger.info("Tum islemler basariyla tamamlandi.")


if __name__ == "__main__":
    main()
