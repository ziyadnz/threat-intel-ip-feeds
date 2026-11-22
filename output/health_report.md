# IP Blacklist Aggregator - Health Report

**Date:** 2026-11-22T03:15:11.833066+00:00
**Duration:** 17.35s
**Successful:** 19/19
**Fresh Fetches:** 18
**Sources Using Cache:** 1

## Cache Usage

Cache reuse is separated from a fresh successful fetch. Duration includes requests, retries, and waits.

| Source | Reason | Cache Observed At (UTC) | Cache Age at Run Start | Fetch Duration |
|--------|--------|-------------------------|------------------------|----------------|
| AbuseIPDB | Scheduled cache reuse: 4h refresh interval; next fetch due 2026-11-22T03:16:23.228545+00:00 | 2026-11-21T23:16:23.228545+00:00 | 3h 58m 48s | 0.16s |

## Deduplication & Source Overlap

| Metric | Value |
|--------|-------|
| Unique to single source | 52,252 |
| Found in multiple sources | 44,243 |
| Max source overlap | 8 |
| Avg sources per IP | 1.88 |

### Per-Source Contribution

| Source | Unique | Shared | Unique % |
|--------|--------|--------|----------|
| RTBH (Turkiye) | 24,303 | 20,755 | 53.9% |
| Stamparm IPsum | 10,424 | 30,162 | 25.7% |
| SGB (Turkiye) | 9,636 | 364 | 96.4% |
| CINS Army | 3,538 | 11,462 | 23.6% |
| Spamhaus DROP | 1,751 | 0 | 100.0% |
| AbuseIPDB | 1,516 | 8,484 | 15.2% |
| Tor Exit Nodes | 355 | 908 | 28.1% |
| GreenSnow | 236 | 2,077 | 10.2% |
| AlienVault OTX | 235 | 84 | 73.7% |
| BinaryDefense | 123 | 763 | 13.9% |
| Spamhaus DROPv6 | 90 | 0 | 100.0% |
| Blocklist.de (all) | 23 | 22,674 | 0.1% |
| Emerging Threats | 15 | 581 | 2.5% |
| Blocklist.de (strongips) | 6 | 277 | 2.1% |
| Blocklist.de (ssh) | 1 | 5,265 | 0.0% |
| Blocklist.de (mail) | 0 | 14,044 | 0.0% |
| Blocklist.de (apache) | 0 | 9,107 | 0.0% |
| Blocklist.de (bots) | 0 | 1,593 | 0.0% |
| Blocklist.de (bruteforcelogin) | 0 | 575 | 0.0% |

### Top Source Pair Overlaps

| Pair | Shared IPs |
|------|-----------|
| Stamparm IPsum & RTBH (Turkiye) | 17,477 |
| Blocklist.de (all) & Blocklist.de (mail) | 14,044 |
| CINS Army & Stamparm IPsum | 11,288 |
| Blocklist.de (all) & RTBH (Turkiye) | 9,948 |
| Blocklist.de (all) & Stamparm IPsum | 9,919 |
| Blocklist.de (all) & Blocklist.de (apache) | 9,107 |
| Stamparm IPsum & AbuseIPDB | 7,871 |
| Blocklist.de (mail) & Blocklist.de (apache) | 7,711 |
| RTBH (Turkiye) & AbuseIPDB | 5,295 |
| Blocklist.de (all) & Blocklist.de (ssh) | 5,261 |

## All Sources

| Source | IPs | Status | Fetch Duration | Details |
|--------|-----|--------|----------------|---------|
| RTBH (Turkiye) | 45,058 | OK | 1.99s | Fresh fetch |
| Stamparm IPsum | 40,586 | OK | 1.14s | Fresh fetch |
| Blocklist.de (all) | 22,697 | OK | 1.13s | Fresh fetch |
| CINS Army | 15,000 | OK | 0.70s | Fresh fetch |
| Blocklist.de (mail) | 14,044 | OK | 1.04s | Fresh fetch |
| AbuseIPDB | 10,000 | CACHED | 0.16s | Scheduled cache reuse: 4h refresh interval; next fetch due 2026-11-22T03:16:23.228545+00:00 |
| SGB (Turkiye) | 10,000 | OK | 9.05s | Fresh fetch |
| Blocklist.de (apache) | 9,107 | OK | 0.60s | Fresh fetch |
| Blocklist.de (ssh) | 5,266 | OK | 0.60s | Fresh fetch |
| GreenSnow | 2,313 | OK | 0.84s | Fresh fetch |
| Spamhaus DROP | 1,751 | OK | 0.17s | Fresh fetch |
| Blocklist.de (bots) | 1,593 | OK | 0.47s | Fresh fetch |
| Tor Exit Nodes | 1,263 | OK | 0.77s | Fresh fetch |
| BinaryDefense | 886 | OK | 0.93s | Fresh fetch |
| Emerging Threats | 596 | OK | 0.72s | Fresh fetch |
| Blocklist.de (bruteforcelogin) | 575 | OK | 0.34s | Fresh fetch |
| AlienVault OTX | 319 | OK | 15.18s | Fresh fetch |
| Blocklist.de (strongips) | 283 | OK | 0.27s | Fresh fetch |
| Spamhaus DROPv6 | 90 | OK | 0.17s | Fresh fetch |

## All sources healthy.
