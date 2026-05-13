# IP Blacklist Aggregator - Health Report

**Date:** 2026-05-13T01:54:04.042957+00:00
**Duration:** 189.69s
**Successful:** 18/20

## Failed Sources This Run

| Source | Error | Cached |
|--------|------|--------|
| SGB (Turkiye) | ConnectTimeout: HTTPSConnectionPool(host='siberguvenlik.gov.tr', port=443): Max retries exceeded with url: /api/address/index?type=ip&page=1 (Caused by ConnectTimeoutError(<HTTPSConnection(host='siber | No cache |

## Deduplication & Source Overlap

| Metric | Value |
|--------|-------|
| Unique to single source | 38,849 |
| Found in multiple sources | 44,624 |
| Max source overlap | 8 |
| Avg sources per IP | 2.02 |

### Per-Source Contribution

| Source | Unique | Shared | Unique % |
|--------|--------|--------|----------|
| RTBH (Turkiye) | 22,351 | 16,918 | 56.9% |
| Stamparm IPsum | 7,490 | 29,607 | 20.2% |
| CINS Army | 3,652 | 11,348 | 24.3% |
| Spamhaus DROP | 1,611 | 0 | 100.0% |
| GreenSnow | 967 | 4,039 | 19.3% |
| BinaryDefense | 811 | 1,576 | 34.0% |
| AbuseIPDB | 781 | 9,219 | 7.8% |
| Tor Exit Nodes | 698 | 656 | 51.6% |
| AlienVault OTX | 212 | 2 | 99.1% |
| Blocklist.de (all) | 120 | 23,478 | 0.5% |
| Spamhaus DROPv6 | 94 | 0 | 100.0% |
| Blocklist.de (strongips) | 52 | 274 | 16.0% |
| Blocklist.de (bots) | 7 | 2,778 | 0.3% |
| Emerging Threats | 3 | 419 | 0.7% |
| DShield | 0 | 0 | N/A |
| Blocklist.de (ssh) | 0 | 4,868 | 0.0% |
| Blocklist.de (mail) | 0 | 13,948 | 0.0% |
| Blocklist.de (apache) | 0 | 9,450 | 0.0% |
| Blocklist.de (bruteforcelogin) | 0 | 1,258 | 0.0% |
| SGB (Turkiye) | 0 | 0 | N/A |

### Top Source Pair Overlaps

| Pair | Shared IPs |
|------|-----------|
| Stamparm IPsum & RTBH (Turkiye) | 15,437 |
| Blocklist.de (all) & Blocklist.de (mail) | 13,947 |
| CINS Army & Stamparm IPsum | 10,400 |
| Blocklist.de (all) & Stamparm IPsum | 9,986 |
| Blocklist.de (all) & Blocklist.de (apache) | 9,450 |
| Stamparm IPsum & AbuseIPDB | 8,382 |
| Blocklist.de (mail) & Blocklist.de (apache) | 7,967 |
| CINS Army & RTBH (Turkiye) | 5,711 |
| RTBH (Turkiye) & AbuseIPDB | 5,120 |
| Blocklist.de (all) & Blocklist.de (ssh) | 4,851 |

## 1 Sources Stale (30+ days)

| Source | Last Success | Consecutive Failures |
|--------|-------------|---------------------|
| SGB (Turkiye) | Never | 4 |

## Consecutively Failing Sources

| Source | Failures | Last Failure | Reason |
|--------|----------|-------------|--------|
| SGB (Turkiye) | 4 | 2026-05-13 | ConnectTimeout: HTTPSConnectionPool(host='siberguvenlik.gov. |

## All Sources

| Source | IPs | Status |
|--------|-----|--------|
| RTBH (Turkiye) | 39,269 | OK |
| Stamparm IPsum | 37,097 | OK |
| Blocklist.de (all) | 23,598 | OK |
| CINS Army | 15,000 | OK |
| Blocklist.de (mail) | 13,948 | OK |
| AbuseIPDB | 10,000 | OK |
| Blocklist.de (apache) | 9,450 | OK |
| GreenSnow | 5,006 | OK |
| Blocklist.de (ssh) | 4,868 | OK |
| Blocklist.de (bots) | 2,785 | OK |
| BinaryDefense | 2,387 | OK |
| Spamhaus DROP | 1,611 | OK |
| Tor Exit Nodes | 1,354 | OK |
| Blocklist.de (bruteforcelogin) | 1,258 | OK |
| Emerging Threats | 422 | OK |
| Blocklist.de (strongips) | 326 | OK |
| AlienVault OTX | 214 | OK |
| Spamhaus DROPv6 | 94 | OK |
| DShield | 0 | EMPTY |
| SGB (Turkiye) | 0 | FAILED |
