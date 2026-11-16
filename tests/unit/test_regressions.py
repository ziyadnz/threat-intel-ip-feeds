"""Regression coverage for throttling, freshness, publishing, and output stability."""

import csv
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import MagicMock, patch

import pytest

from threat_intel.domain.entities import (
    CollectionResult, IPAddress, SourceHealthRecord, SourceResult,
    ThreatCategory, ThreatIndicator, WhitelistEntry,
)
from threat_intel.domain.services import OverlapAnalyzer, WhitelistFilter
from threat_intel.infrastructure.http.requests_client import RequestsClient, HttpError
from threat_intel.infrastructure.sources.api_sources import AbuseIPDBSource, AlienVaultOTXSource
from threat_intel.infrastructure.writers.csv_writer import CSVWriter
from threat_intel.infrastructure.writers.raw_writer import RawIPv4Writer
from threat_intel.infrastructure.writers.stix_writer import STIXBundleWriter
from threat_intel.infrastructure.notification.github_notifier import GitHubIssueNotifier
from threat_intel.application.use_cases.write_outputs import WriteOutputsUseCase
from threat_intel.application.use_cases.collect_threat_intel import CollectThreatIntelUseCase
from threat_intel.infrastructure.cache.source_cache import SourceCacheRepository

NOW = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)


def result(now=NOW, cached=False):
    ip = IPAddress.parse("8.8.4.4")
    return CollectionResult(now, 1, [SourceResult("A", frozenset({ip}), from_cache=cached)],
                            [ThreatIndicator.create(ip, frozenset({"A"}), ThreatCategory.ATTACKER, now)])


def cache(tmp_path, name, now, ips=("8.8.4.4",)):
    path = tmp_path / name
    path.write_text(json.dumps({"timestamp": now.isoformat(), "ips": list(ips)}))
    return path


@pytest.mark.parametrize("header", ["120", format_datetime(NOW + timedelta(seconds=120))])
def test_retry_after_is_honored(header):
    client = RequestsClient()
    limited = MagicMock(status_code=429, text="limited", headers={"Retry-After": header})
    ok = MagicMock(status_code=200, text="ok")
    with patch.object(client._session, "get", side_effect=[limited, ok]), \
            patch("threat_intel.infrastructure.http.requests_client.datetime") as clock, \
            patch("threat_intel.infrastructure.http.requests_client.time.sleep") as sleep:
        clock.now.return_value = NOW
        assert client.get("https://example.invalid") == "ok"
        sleep.assert_called_once_with(120)
    client.close()


def test_sessions_are_thread_local_and_all_closed():
    import threading
    client = RequestsClient()
    barrier = threading.Barrier(3)
    def worker(_):
        session = client._session
        barrier.wait()
        return session
    with ThreadPoolExecutor(max_workers=3) as pool:
        sessions = list(pool.map(worker, range(3)))
    assert len({id(s) for s in sessions}) == 3
    with patch.object(sessions[0], "close") as close:
        client.close()
        close.assert_called_once()


@pytest.mark.parametrize("entry,block", [
    ("8.8.8.8", "8.8.8.0/24"), ("8.8.8.0/25", "8.8.8.0/24"),
    ("2606:4700::1111", "2606:4700::/32"),
])
def test_whitelist_protects_overlapping_ranges(entry, block):
    entry = WhitelistEntry.parse(entry)
    ip = IPAddress.parse(block)
    assert entry.covers(ip)
    assert WhitelistFilter([entry]).is_whitelisted(ip)


def test_equivalent_networks_and_ipv6_addresses_deduplicate():
    assert IPAddress.parse("8.8.8.1/24") == IPAddress.parse("8.8.8.0/24")
    assert IPAddress.parse("2606:4700:0:0:0:0:0:1111") == IPAddress.parse("2606:4700::1111")


@pytest.mark.parametrize("age,expected_calls", [(3.99, 0), (4, 1), (5, 1)])
def test_abuseipdb_refreshes_by_elapsed_four_hours(tmp_path, age, expected_calls):
    now = datetime.now(timezone.utc)
    cache(tmp_path, "abuseipdb_cache.json", now - timedelta(hours=age))
    http = MagicMock()
    http.get_json.return_value = {"data": [{"ipAddress": "1.2.3.4"}]}
    source = AbuseIPDBSource(http, "key", str(tmp_path))
    outcome = source.fetch_result()
    assert http.get_json.call_count == expected_calls
    assert outcome.from_cache == (expected_calls == 0)
    assert outcome.observed_at is not None
    assert outcome.error is None


def test_abuseipdb_fallback_preserves_cache_and_reports_failure(tmp_path):
    path = cache(tmp_path, "abuseipdb_cache.json", NOW - timedelta(days=1))
    before = path.read_bytes()
    http = MagicMock()
    http.get_json.side_effect = RuntimeError("blocked")
    outcome = AbuseIPDBSource(http, "key", str(tmp_path)).fetch_result()
    assert outcome.from_cache and "blocked" in outcome.error
    assert path.read_bytes() == before


def test_missing_api_key_is_skipped(tmp_path):
    http = MagicMock()
    outcome = AbuseIPDBSource(http, "", str(tmp_path)).fetch_result()
    assert outcome.skipped
    http.get_json.assert_not_called()


def pulse(ip="1.2.3.4", next_page=None):
    return {"results": [{"indicators": [{"type": "IPv4", "indicator": ip}]}], "next": next_page}


def test_otx_stops_after_end_batch(tmp_path):
    http = MagicMock()
    http.get_json.return_value = pulse()
    outcome = AlienVaultOTXSource(http, "key", str(tmp_path)).fetch_result()
    assert outcome.is_success
    assert http.get_json.call_count == 3  # Already submitted bounded batch; no further pages.
    assert len(outcome.ips) == 1


def test_otx_partial_failure_does_not_overwrite_complete_cache(tmp_path):
    path = cache(tmp_path, "otx_cache.json", NOW - timedelta(days=1))
    before = path.read_bytes()
    http = MagicMock()
    def get(url, **kwargs):
        if url.endswith("page=2"):
            raise HttpError(403, "blocked")
        return pulse(next_page="more")
    http.get_json.side_effect = get
    outcome = AlienVaultOTXSource(http, "key", str(tmp_path), max_pages=3).fetch_result()
    assert outcome.error and outcome.from_cache
    assert {ip.raw for ip in outcome.ips} == {"8.8.4.4", "1.2.3.4"}
    assert path.read_bytes() == before
    assert http.get_json.call_count == 3  # Permanent failure not retried by pagination layer.


def test_cached_result_does_not_reset_failures_or_advance_freshness(tmp_path):
    health = MagicMock()
    old = SourceHealthRecord("A", last_success=NOW - timedelta(days=2), consecutive_failures=2)
    health.load_all.return_value = {"A": old}
    source = MagicMock()
    source.name = "A"
    source.fetch_result.return_value = result(cached=True).source_results[0]
    whitelist = MagicMock()
    whitelist.load.return_value = []
    uc = CollectThreatIntelUseCase([source], whitelist, health, SourceCacheRepository(str(tmp_path)))
    uc.execute()
    updated = health.save_all.call_args.args[0]["A"]
    assert updated.last_success == old.last_success
    assert updated.consecutive_failures == 2


def test_writer_failure_preserves_all_existing_outputs(tmp_path):
    path = tmp_path / "hourlyIPv4.txt"
    path.write_text("previous complete feed\n")
    writer = MagicMock()
    writer.format_name = "broken"
    writer.write.side_effect = OSError("disk full")
    uc = WriteOutputsUseCase([RawIPv4Writer(), writer], str(tmp_path))
    assert not uc.execute(result())
    assert path.read_text() == "previous complete feed\n"
    assert not list(tmp_path.parent.glob(".feeds-*"))


def test_publish_failure_restores_already_replaced_files(tmp_path):
    for name in ("blacklist.csv", "hourlyIPv4.txt"):
        (tmp_path / name).write_text("previous\n")
    import os
    real_replace = os.replace
    def fail(src, dest):
        if str(src).endswith("stage/hourlyIPv4.txt"):
            raise OSError("simulated publish failure")
        return real_replace(src, dest)
    with patch("threat_intel.application.use_cases.write_outputs.os.replace", side_effect=fail):
        assert not WriteOutputsUseCase([CSVWriter(), RawIPv4Writer()], str(tmp_path)).execute(result())
    assert (tmp_path / "blacklist.csv").read_text() == "previous\n"
    assert (tmp_path / "hourlyIPv4.txt").read_text() == "previous\n"


def test_observation_times_and_stix_stay_stable_for_cached_data(tmp_path):
    uc = WriteOutputsUseCase([CSVWriter(), STIXBundleWriter()], str(tmp_path))
    assert uc.execute(result())
    stix = (tmp_path / "stix_bundle.json").read_bytes()
    csv_data = (tmp_path / "blacklist.csv").read_bytes()
    assert uc.execute(result(NOW + timedelta(hours=1), cached=True))
    assert (tmp_path / "blacklist.csv").read_bytes() == csv_data
    assert (tmp_path / "stix_bundle.json").read_bytes() == stix
    assert uc.execute(result(NOW + timedelta(hours=2)))
    with (tmp_path / "blacklist.csv").open() as f:
        row = next(csv.DictReader(f))
    assert row["first_seen"] == NOW.isoformat()
    assert row["last_seen"] == (NOW + timedelta(hours=2)).isoformat()
    assert (tmp_path / "stix_bundle.json").read_bytes() == stix


def test_stix_order_independent_of_collection_order(tmp_path):
    r = result()
    other = ThreatIndicator.create(IPAddress.parse("1.2.3.4"), frozenset({"A"}), ThreatCategory.ATTACKER, NOW)
    r.indicators.append(other)
    writer = STIXBundleWriter()
    writer.write(r, str(tmp_path))
    before = (tmp_path / "stix_bundle.json").read_bytes()
    r.indicators.reverse()
    writer.write(r, str(tmp_path))
    assert (tmp_path / "stix_bundle.json").read_bytes() == before


def test_overlap_metrics_match_direct_set_reference():
    import random
    rng = random.Random(42)
    names = ["A", "B", "C", "D"]
    data = {str(i): frozenset(rng.sample(names, rng.randint(1, 4))) for i in range(100)}
    metrics = OverlapAnalyzer.analyze(data, names)
    for name in names:
        assert metrics.per_source_unique[name] == sum(s == {name} for s in data.values())
        assert metrics.per_source_shared[name] == sum(name in s and len(s) > 1 for s in data.values())
    pairs = {f"{a} & {b}": sum(a in s and b in s for s in data.values())
             for i, a in enumerate(names) for b in names[i + 1:]}
    assert metrics.top_pair_overlaps == dict(sorted(pairs.items(), key=lambda p: -p[1]))


def test_notifier_updates_existing_issue_instead_of_creating_duplicate():
    notifier = GitHubIssueNotifier()
    def gh(args):
        out = '[{"number": 12}]' if args[:2] == ["issue", "list"] else ""
        return subprocess.CompletedProcess(args, 0, out, "")
    with patch.object(notifier, "_is_ci", return_value=True), patch.object(notifier, "_gh", side_effect=gh) as run:
        notifier.notify("Source Health Alert", "updated report")
    calls = [c.args[0] for c in run.call_args_list]
    assert any(c[:3] == ["issue", "edit", "12"] for c in calls)
    assert not any(c[:2] == ["issue", "create"] for c in calls)


def test_cli_fatal_exception_is_distinct_from_partial_source_failure():
    from threat_intel.presentation.cli import run
    with patch("threat_intel.presentation.cli._main", side_effect=RuntimeError("fatal")):
        with pytest.raises(SystemExit) as exit:
            run()
    assert exit.value.code == 2
    with patch("threat_intel.presentation.cli._main", side_effect=SystemExit(1)):
        with pytest.raises(SystemExit) as exit:
            run()
    assert exit.value.code == 1


def test_generic_cache_exposes_original_observation_time(tmp_path):
    repo = SourceCacheRepository(str(tmp_path))
    repo.save("A", {IPAddress.parse("1.2.3.4")})
    outcome = repo.load_result("A")
    assert outcome.from_cache
    assert outcome.observed_at is not None
    assert outcome.ips == {IPAddress.parse("1.2.3.4")}


def test_unreadable_cache_does_not_crash_failure_fallback(tmp_path):
    (tmp_path / "a.json").write_text('{"ips": [null]}')
    outcome = SourceCacheRepository(str(tmp_path)).load_result("A")
    assert not outcome.ips


def test_stix_modified_advances_only_for_changed_indicator_content(tmp_path):
    uc = WriteOutputsUseCase([CSVWriter(), STIXBundleWriter()], str(tmp_path))
    assert uc.execute(result())
    r = result(NOW + timedelta(hours=1))
    r.indicators = [replace(r.indicators[0], category=ThreatCategory.SCANNER)]
    assert uc.execute(r)
    objects = json.loads((tmp_path / "stix_bundle.json").read_text())["objects"]
    indicator = objects[1]
    assert indicator["created"] == NOW.isoformat()
    assert indicator["modified"] == r.timestamp.isoformat()
    assert indicator["labels"] == ["scanner"]


def test_otx_outer_retry_respects_server_delay(tmp_path):
    http = MagicMock()
    http.get_json.side_effect = [HttpError(429, "limited", retry_after=120), pulse()]
    with patch("threat_intel.infrastructure.sources.api_sources.time.sleep") as sleep:
        outcome = AlienVaultOTXSource(http, "key", str(tmp_path), max_pages=1).fetch_result()
    sleep.assert_called_once_with(120)
    assert outcome.is_success


def test_otx_partial_without_cache_is_not_labeled_cached(tmp_path):
    http = MagicMock()
    def get(url, **kwargs):
        if url.endswith("page=2"):
            raise HttpError(403, "blocked")
        return pulse(next_page="more")
    http.get_json.side_effect = get
    outcome = AlienVaultOTXSource(http, "key", str(tmp_path), max_pages=2).fetch_result()
    assert outcome.partial and outcome.error and not outcome.from_cache
    assert outcome.ips
    assert not (tmp_path / "otx_cache.json").exists()


def test_invalid_staged_json_is_not_published(tmp_path):
    original = '{"previous": true}'
    (tmp_path / "blacklist_full.json").write_text(original)
    class InvalidWriter:
        format_name = "Full JSON"
        def write(self, r, output_dir):
            from pathlib import Path
            path = Path(output_dir) / "blacklist_full.json"
            path.write_text('{"truncated":')
            return str(path)
    assert not WriteOutputsUseCase([InvalidWriter()], str(tmp_path)).execute(result())
    assert (tmp_path / "blacklist_full.json").read_text() == original
