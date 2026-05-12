# IP Blacklist Aggregator - Health Report

**Date:** 2026-05-12T22:01:04.772314+00:00
**Duration:** 194.89s
**Successful:** 19/20

## Failed Sources This Run

| Source | Error | Cached |
|--------|------|--------|
| SGB (Turkiye) | ConnectTimeout: HTTPSConnectionPool(host='siberguvenlik.gov.tr', port=443): Max retries exceeded with url: /api/address/index?type=ip&page=1 (Caused by ConnectTimeoutError(<HTTPSConnection(host='siber | No cache |

## Deduplication & Source Overlap

| Metric | Value |
|--------|-------|
| Unique to single source | 130,265 |
| Found in multiple sources | 46,982 |
| Max source overlap | 9 |
| Avg sources per IP | 1.54 |

### Per-Source Contribution

| Source | Unique | Shared | Unique % |
|--------|--------|--------|----------|
| DShield | 91,970 | 15,805 | 85.3% |
| RTBH (Turkiye) | 21,570 | 17,493 | 55.2% |
| Stamparm IPsum | 6,710 | 29,136 | 18.7% |
| CINS Army | 5,457 | 9,543 | 36.4% |
| Spamhaus DROP | 1,611 | 0 | 100.0% |
| GreenSnow | 1,023 | 3,239 | 24.0% |
| AbuseIPDB | 780 | 9,220 | 7.8% |
| BinaryDefense | 613 | 1,320 | 31.7% |
| AlienVault OTX | 212 | 2 | 99.1% |
| Blocklist.de (all) | 166 | 23,410 | 0.7% |
| Spamhaus DROPv6 | 94 | 0 | 100.0% |
| Blocklist.de (strongips) | 52 | 273 | 16.0% |
| Tor Exit Nodes | 4 | 1,349 | 0.3% |
| Emerging Threats | 2 | 420 | 0.5% |
| Blocklist.de (bots) | 1 | 2,830 | 0.0% |
| Blocklist.de (ssh) | 0 | 4,785 | 0.0% |
| Blocklist.de (mail) | 0 | 13,946 | 0.0% |
| Blocklist.de (apache) | 0 | 9,442 | 0.0% |
| Blocklist.de (bruteforcelogin) | 0 | 1,262 | 0.0% |
| SGB (Turkiye) | 0 | 0 | N/A |

### Top Source Pair Overlaps

| Pair | Shared IPs |
|------|-----------|
| Stamparm IPsum & RTBH (Turkiye) | 15,491 |
| DShield & Stamparm IPsum | 14,261 |
| Blocklist.de (all) & Blocklist.de (mail) | 13,946 |
| Blocklist.de (all) & Blocklist.de (apache) | 9,442 |
| DShield & RTBH (Turkiye) | 8,680 |
| CINS Army & Stamparm IPsum | 8,476 |
| Blocklist.de (all) & Stamparm IPsum | 8,339 |
| Stamparm IPsum & AbuseIPDB | 8,028 |
| Blocklist.de (mail) & Blocklist.de (apache) | 7,967 |
| RTBH (Turkiye) & AbuseIPDB | 5,109 |

## 1 Sources Stale (30+ days)

| Source | Last Success | Consecutive Failures |
|--------|-------------|---------------------|
| SGB (Turkiye) | Never | 2 |

## Consecutively Failing Sources

| Source | Failures | Last Failure | Reason |
|--------|----------|-------------|--------|
| SGB (Turkiye) | 2 | 2026-05-12 | ConnectTimeout: HTTPSConnectionPool(host='siberguvenlik.gov. |

## All Sources

| Source | IPs | Status |
|--------|-----|--------|
| DShield | 107,775 | OK |
| RTBH (Turkiye) | 39,063 | OK |
| Stamparm IPsum | 35,846 | OK |
| Blocklist.de (all) | 23,576 | OK |
| CINS Army | 15,000 | OK |
| Blocklist.de (mail) | 13,946 | OK |
| AbuseIPDB | 10,000 | OK |
| Blocklist.de (apache) | 9,442 | OK |
| Blocklist.de (ssh) | 4,785 | OK |
| GreenSnow | 4,262 | OK |
| Blocklist.de (bots) | 2,831 | OK |
| BinaryDefense | 1,933 | OK |
| Spamhaus DROP | 1,611 | OK |
| Tor Exit Nodes | 1,353 | OK |
| Blocklist.de (bruteforcelogin) | 1,262 | OK |
| Emerging Threats | 422 | OK |
| Blocklist.de (strongips) | 325 | OK |
| AlienVault OTX | 214 | OK |
| Spamhaus DROPv6 | 94 | OK |
| SGB (Turkiye) | 0 | FAILED |
