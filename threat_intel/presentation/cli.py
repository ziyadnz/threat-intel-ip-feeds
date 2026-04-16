"""Presentation layer — CLI entry point and composition root.

This is the ONLY place where concrete implementations are instantiated
and wired together. All dependency injection happens here.
No business logic lives in this file.
"""

from __future__ import annotations

import logging
import os
import sys

from threat_intel.domain.entities import CollectionResult

# Infrastructure — concrete implementations
from threat_intel.infrastructure.http.requests_client import RequestsClient
from threat_intel.infrastructure.sources.global_sources import (
    BinaryDefenseSource,
    BlocklistDeSource,
    CinsArmySource,
    DShieldSource,
    EmergingThreatsSource,
    FeodoTrackerSource,
    GreenSnowSource,
    SpamhausDropSource,
    SpamhausDropV6Source,
    StamparmIpsumSource,
    TorExitSource,
)
from threat_intel.infrastructure.sources.regional_sources import (
    RtbhSource,
    UsomSource,
)
from threat_intel.infrastructure.sources.api_sources import (
    AbuseIPDBSource,
    AlienVaultOTXSource,
)
from threat_intel.infrastructure.writers.raw_writer import (
    AnnotatedIPv4Writer,
    AnnotatedIPv6Writer,
    RawIPv4Writer,
)
from threat_intel.infrastructure.writers.csv_writer import CSVWriter
from threat_intel.infrastructure.writers.stix_writer import STIXBundleWriter
from threat_intel.infrastructure.writers.json_writer import FullJSONWriter
from threat_intel.infrastructure.cache.source_cache import SourceCacheRepository
from threat_intel.infrastructure.health.json_repository import JsonHealthRepository
from threat_intel.infrastructure.health.markdown_report_writer import (
    MarkdownReportWriter,
)
from threat_intel.infrastructure.whitelist.file_repository import (
    FileWhitelistRepository,
)
from threat_intel.infrastructure.notification.github_notifier import (
    GitHubIssueNotifier,
)

# Application use cases
from threat_intel.application.use_cases.collect_threat_intel import (
    CollectThreatIntelUseCase,
)
from threat_intel.application.use_cases.write_outputs import WriteOutputsUseCase
from threat_intel.application.use_cases.report_health import ReportHealthUseCase

logger = logging.getLogger(__name__)


class AppConfig:
    """Loads configuration from environment variables and defaults."""

    def __init__(self):
        self.base_dir = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        ))
        self.output_dir = os.path.join(self.base_dir, "output")
        self.whitelist_file = os.path.join(self.base_dir, "whitelist.txt")
        self.health_file = os.path.join(self.output_dir, "source_health.json")
        self.log_file = os.path.join(self.base_dir, "aggregator.log")

        # API keys from environment
        self.abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        self.otx_key = os.environ.get("OTX_API_KEY", "")

        # Tuning
        self.request_timeout = int(os.environ.get("REQUEST_TIMEOUT", "60"))
        self.max_retries = int(os.environ.get("MAX_RETRIES", "3"))
        self.connector_limit = int(os.environ.get("CONNECTOR_LIMIT", "30"))
        self.min_success_ratio = float(os.environ.get("MIN_SUCCESS_RATIO", "0.2"))
        self.stale_threshold_days = int(os.environ.get("STALE_THRESHOLD_DAYS", "30"))
        self.ipsum_min_score = int(os.environ.get("IPSUM_MIN_SCORE", "2"))


def _build_sources(http: RequestsClient, config: AppConfig) -> list:
    """Build all threat source instances with injected HTTP client."""
    return [
        SpamhausDropSource(http),
        SpamhausDropV6Source(http),
        FeodoTrackerSource(http),
        DShieldSource(http),
        BlocklistDeSource(http, "all"),
        BlocklistDeSource(http, "ssh"),
        BlocklistDeSource(http, "mail"),
        BlocklistDeSource(http, "apache"),
        BlocklistDeSource(http, "bots"),
        BlocklistDeSource(http, "bruteforcelogin"),
        BlocklistDeSource(http, "strongips"),
        CinsArmySource(http),
        EmergingThreatsSource(http),
        BinaryDefenseSource(http),
        GreenSnowSource(http),
        TorExitSource(http),
        StamparmIpsumSource(http, min_score=config.ipsum_min_score),
        UsomSource(http),
        RtbhSource(http),
        AbuseIPDBSource(http, config.abuseipdb_key, config.output_dir),
        AlienVaultOTXSource(http, config.otx_key, config.output_dir),
    ]


def _build_writers() -> list:
    """Build all output writer instances."""
    return [
        RawIPv4Writer(),
        AnnotatedIPv4Writer(),
        AnnotatedIPv6Writer(),
        CSVWriter(),
        STIXBundleWriter(),
        FullJSONWriter(),
    ]


def _print_summary(result: CollectionResult):
    """Print human-readable summary to console."""
    ipv4_total = len(result.ipv4_ips) + len(result.ipv4_cidrs)
    ipv6_total = len(result.ipv6_ips) + len(result.ipv6_cidrs)
    fail_count = len(result.failed_sources)
    o = result.overlap

    print(f"\n{'=' * 60}")
    print(f"  IP BLACKLIST AGGREGATOR — SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Time        : {result.timestamp.isoformat()}")
    print(f"  Duration    : {result.elapsed_seconds}s")
    print(f"  Sources     : {result.successful_sources}/{result.total_sources} OK")
    if fail_count:
        print(f"  FAILURES    : {fail_count} sources failed")
    if result.whitelist_filtered_count:
        print(f"  Whitelist   : {result.whitelist_filtered_count} IPs filtered")
    print(f"  IPv4        : {len(result.ipv4_ips):,} IPs + {len(result.ipv4_cidrs):,} CIDRs")
    print(f"  IPv6        : {len(result.ipv6_ips):,} IPs + {len(result.ipv6_cidrs):,} CIDRs")
    print(f"  Total       : {ipv4_total + ipv6_total:,}")
    if o.unique_single_source or o.found_in_multiple:
        print(f"  {'—' * 56}")
        print(f"  DEDUPLICATION:")
        print(f"  Single src  : {o.unique_single_source:,}")
        print(f"  Multi src   : {o.found_in_multiple:,}")
        print(f"  Max overlap : {o.max_source_overlap} sources")
        print(f"  Avg src/IP  : {o.avg_sources_per_ip}")
    print(f"{'=' * 60}")

    print(f"  SOURCES:")
    print(f"  {'—' * 56}")
    failed_names = {sr.source_name for sr in result.failed_sources}
    cached_names = {sr.source_name for sr in result.source_results if sr.from_cache}
    for sr in sorted(result.source_results, key=lambda s: -s.ip_count):
        if sr.source_name in cached_names:
            mark = "C"
            suffix = " [CACHED]"
        elif sr.source_name in failed_names:
            mark = "X"
            suffix = ""
        elif sr.ip_count > 0:
            mark = "+"
            suffix = ""
        else:
            mark = "?"
            suffix = ""
        u = o.per_source_unique.get(sr.source_name, "")
        s = o.per_source_shared.get(sr.source_name, "")
        extra = f"  (uniq:{u} ovlp:{s})" if u != "" else ""
        print(f"  {mark} {sr.source_name:<40} {sr.ip_count:>8,}{extra}{suffix}")

    if result.whitelist_hits:
        print(f"{'=' * 60}")
        print(f"  WHITELIST FILTERED:")
        print(f"  {'—' * 56}")
        for hit in sorted(result.whitelist_hits, key=lambda h: h.ip.raw):
            sources_str = ", ".join(sorted(hit.sources))
            print(f"  - {hit.ip.raw:<20} ← {sources_str}")

    if result.failed_sources:
        print(f"{'=' * 60}")
        print(f"  ERRORS:")
        for sr in result.failed_sources:
            print(f"  ! {sr.source_name}: {(sr.error or '')[:80]}")

    print(f"{'=' * 60}")
    print(f"  Output: output/hourlyIPv4.txt, blacklist.csv, stix_bundle.json")
    print(f"{'=' * 60}\n")


def _main():
    """Application entry point — composition root."""
    config = AppConfig()

    # Logging setup (presentation concern)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(config.log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )

    print(r"""
    +======================================================+
    |       IP BLACKLIST AGGREGATOR v6.0                    |
    |       Clean Architecture + Thread Parallelism         |
    |  21 sources | requests | STIX | CSV | Dedup Metrics   |
    +======================================================+
    """)

    # -- Wire dependencies (composition root) --
    http = RequestsClient(
        default_timeout=config.request_timeout,
        max_retries=config.max_retries,
    )

    try:
        sources = _build_sources(http, config)
        writers = _build_writers()
        health_repo = JsonHealthRepository(config.health_file)
        whitelist_repo = FileWhitelistRepository(config.whitelist_file)
        source_cache = SourceCacheRepository(
            os.path.join(config.output_dir, "source_cache")
        )
        notifier = GitHubIssueNotifier()
        report_writer = MarkdownReportWriter()

        # -- Execute use cases --

        # 1. Collect (parallel via threads)
        collect_uc = CollectThreatIntelUseCase(
            sources=sources,
            whitelist_repo=whitelist_repo,
            health_repo=health_repo,
            source_cache=source_cache,
        )
        result = collect_uc.execute()

        # 2. Write outputs
        write_uc = WriteOutputsUseCase(
            writers=writers,
            output_dir=config.output_dir,
            min_success_ratio=config.min_success_ratio,
        )
        wrote = write_uc.execute(result)

        # 3. Print summary
        _print_summary(result)

        # 4. Health report + notify
        report_uc = ReportHealthUseCase(
            health_repo=health_repo,
            report_writer=report_writer,
            notifier=notifier,
            output_dir=config.output_dir,
            stale_threshold_days=config.stale_threshold_days,
        )
        report_uc.execute(result)

        # 5. Exit code
        if not wrote:
            logger.critical("Output files NOT written. Exit code: 2")
            sys.exit(2)
        if result.failed_sources:
            logger.warning(
                f"{len(result.failed_sources)} sources failed. Exit code: 1"
            )
            sys.exit(1)

        logger.info("All operations completed successfully.")

    finally:
        http.close()


def run():
    """Entry point."""
    _main()
