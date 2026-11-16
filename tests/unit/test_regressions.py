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


@pytest.mark.parametrize("header", ["20", format_datetime(NOW + timedelta(seconds=20))])
def test_retry_after_is_honored(header):
    client = RequestsClient()
    limited = MagicMock(status_code=429, text="limited", headers={"Retry-After": header})
    ok = MagicMock(status_code=200, text="ok")
    with patch.object(client._session, "get", side_effect=[limited, ok]), \
            patch("threat_intel.infrastructure.http.requests_client.datetime") as clock, \
            patch("threat_intel.infrastructure.http.requests_client.time.sleep") as sleep:
        clock.now.return_value = NOW
        assert client.get("https://example.invalid") == "ok"
        sleep.assert_called_once_with(20)
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
    http.get_json.side_effect = [HttpError(429, "limited", retry_after=20), pulse()]
    with patch("threat_intel.infrastructure.sources.api_sources.time.sleep") as sleep:
        outcome = AlienVaultOTXSource(http, "key", str(tmp_path), max_pages=1).fetch_result()
    sleep.assert_called_once_with(20)
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


@pytest.mark.parametrize("header", ["31", "120", format_datetime(NOW + timedelta(seconds=120))])
def test_long_cooldown_defers_without_sleeping_or_retrying(header):
    from threat_intel.infrastructure.http.requests_client import RetryDeferred
    client = RequestsClient()
    limited = MagicMock(status_code=429, text="limited", headers={"Retry-After": header})
    with patch.object(client._session, "get", return_value=limited) as get, \
            patch("threat_intel.infrastructure.http.requests_client.datetime") as clock, \
            patch("threat_intel.infrastructure.http.requests_client.time.sleep") as sleep:
        clock.now.return_value = NOW
        with pytest.raises(RetryDeferred):
            client.get("https://provider.example/page1")
        with pytest.raises(RetryDeferred):
            client.get("https://provider.example/page2")
        assert get.call_count == 1
        sleep.assert_not_called()
    client.close()


def test_429_without_retry_after_uses_slower_backoff_and_jitter():
    client = RequestsClient()
    limited = MagicMock(status_code=429, text="limited", headers={})
    ok = MagicMock(status_code=200, text="ok")
    with patch.object(client._session, "get", side_effect=[limited, limited, ok]), \
            patch("threat_intel.infrastructure.http.requests_client.random.uniform", return_value=0.5), \
            patch("threat_intel.infrastructure.http.requests_client.time.sleep") as sleep:
        assert client.get("https://provider.example") == "ok"
        assert [call.args[0] for call in sleep.call_args_list] == [10.5, 30.5]
    client.close()


def test_exactly_30_seconds_is_still_awaited():
    client = RequestsClient()
    limited = MagicMock(status_code=503, text="busy", headers={"Retry-After": "30"})
    ok = MagicMock(status_code=200, text="ok")
    with patch.object(client._session, "get", side_effect=[limited, ok]), \
            patch("threat_intel.infrastructure.http.requests_client.time.sleep") as sleep:
        assert client.get("https://provider.example") == "ok"
        sleep.assert_called_once_with(30)
    client.close()


def test_deferred_host_does_not_block_other_sources():
    from threat_intel.infrastructure.http.requests_client import RetryDeferred
    client = RequestsClient()
    limited = MagicMock(status_code=503, text="busy", headers={"Retry-After": "120"})
    ok = MagicMock(status_code=200, text="ok")
    with patch.object(client._session, "get", side_effect=[limited, ok]) as get:
        with pytest.raises(RetryDeferred):
            client.get("https://blocked.example/feed")
        assert client.get("https://healthy.example/feed") == "ok"
        assert get.call_count == 2
    client.close()


def test_otx_deferral_stops_later_batches_and_outer_retries(tmp_path):
    from threat_intel.infrastructure.http.requests_client import RetryDeferred
    path = cache(tmp_path, "otx_cache.json", NOW - timedelta(days=1))
    before = path.read_bytes()
    http = MagicMock()
    http.get_json.side_effect = RetryDeferred(429, 120, 30)
    with patch("threat_intel.infrastructure.sources.api_sources.time.sleep") as sleep:
        outcome = AlienVaultOTXSource(http, "key", str(tmp_path)).fetch_result()
    assert http.get_json.call_count == 3  # Only the already submitted batch.
    sleep.assert_not_called()
    assert outcome.from_cache and outcome.error
    assert path.read_bytes() == before


def test_abuseipdb_long_cooldown_uses_cache_without_waiting(tmp_path):
    path = cache(tmp_path, "abuseipdb_cache.json", NOW - timedelta(days=1))
    before = path.read_bytes()
    client = RequestsClient()
    limited = MagicMock(status_code=429, text="limited", headers={"Retry-After": "120"})
    with patch.object(client._session, "get", return_value=limited) as get, \
            patch("threat_intel.infrastructure.http.requests_client.time.sleep") as sleep:
        outcome = AbuseIPDBSource(client, "key", str(tmp_path)).fetch_result()
    assert get.call_count == 1
    sleep.assert_not_called()
    assert outcome.from_cache and "deferring host" in outcome.error
    assert path.read_bytes() == before
    client.close()


def health_report(r):
    from threat_intel.application.use_cases.report_health import ReportHealthUseCase
    return ReportHealthUseCase(MagicMock(), MagicMock(), MagicMock(), "/tmp/unused")._build_report(
        r, r.failed_sources, [], []
    )


@pytest.mark.parametrize("reason", [
    "Scheduled cache reuse: 4h refresh interval; next fetch due tomorrow",
    "Fetch failed: Timeout: Read timed out",
    "Fetch failed: HttpError: HTTP 503: unavailable",
    "Fetch failed: RetryDeferred: HTTP 429: Retry-After 120s exceeds 30s budget",
])
def test_health_report_explains_cache_reason_age_and_duration(reason):
    r = result(cached=True)
    r.source_results = [replace(r.source_results[0], cache_reason=reason,
                                elapsed_seconds=12.34, observed_at=NOW - timedelta(hours=2))]
    report = health_report(r)
    assert "## Cache Usage" in report
    assert reason in report
    assert "2h 0m 0s" in report
    assert "12.34s" in report
    assert "**Fresh Fetches:** 0" in report
    assert "**Sources Using Cache:** 1" in report


def test_health_report_does_not_confuse_slow_success_with_cache():
    r = result()
    r.source_results = [replace(r.source_results[0], elapsed_seconds=104.41)]
    report = health_report(r)
    assert "No source used cached data in this run." in report
    assert "104.41s | Fresh fetch" in report
    assert "**Sources Using Cache:** 0" in report


def test_health_report_escapes_http_html_and_table_delimiters():
    r = result(cached=True)
    r.source_results = [replace(r.source_results[0], error="HTTP 503: <html>\nblocked|retry",
                                cache_reason="HTTP 503: <html>\nblocked|retry")]
    report = health_report(r)
    assert "<html>" not in report
    assert "&lt;html&gt; blocked\\|retry" in report
    assert "| A | HTTP 503: &lt;html&gt; blocked\\|retry |" in report


def test_generic_source_timeout_keeps_reason_and_measures_duration(tmp_path):
    import requests
    source = MagicMock()
    source.name = "A"
    source.fetch_result.side_effect = requests.exceptions.Timeout("read timed out")
    repo = SourceCacheRepository(str(tmp_path))
    repo.save("A", {IPAddress.parse("8.8.4.4")})
    uc = CollectThreatIntelUseCase([source], MagicMock(), MagicMock(), repo)
    outcome = uc._safe_fetch(source)
    assert outcome.from_cache
    assert "Timeout" in outcome.cache_reason
    assert outcome.elapsed_seconds is not None and outcome.elapsed_seconds >= 0
    assert outcome.observed_at is not None


def test_abuseipdb_scheduled_cache_explains_next_refresh(tmp_path):
    now = datetime.now(timezone.utc)
    cache(tmp_path, "abuseipdb_cache.json", now - timedelta(hours=1))
    outcome = AbuseIPDBSource(MagicMock(), "key", str(tmp_path)).fetch_result()
    assert outcome.from_cache and outcome.error is None
    assert "Scheduled cache reuse: 4h" in outcome.cache_reason
    assert "next fetch due" in outcome.cache_reason


def test_json_source_details_include_cache_cause_and_fetch_duration(tmp_path):
    from threat_intel.infrastructure.writers.json_writer import FullJSONWriter
    r = result(cached=True)
    r.source_results = [replace(r.source_results[0], cache_reason="Scheduled reuse",
                                elapsed_seconds=0.02, observed_at=NOW - timedelta(hours=1))]
    path = FullJSONWriter().write(r, str(tmp_path))
    with open(path) as f:
        details = json.load(f)["source_details"]["A"]
    assert details["from_cache"] is True
    assert details["cache_reason"] == "Scheduled reuse"
    assert details["elapsed_seconds"] == 0.02
    assert details["observed_at"] == (NOW - timedelta(hours=1)).isoformat()
