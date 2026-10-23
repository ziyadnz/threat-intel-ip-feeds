# IP Blacklist Aggregator - Health Report

**Date:** 2026-10-23T13:27:09.037091+00:00
**Duration:** 73.44s
**Successful:** 18/19

## Failed Sources This Run

| Source | Error | Cached |
|--------|------|--------|
| GreenSnow | ReadTimeout: HTTPSConnectionPool(host='blocklist.greensnow.co', port=443): Read timed out. (read timeout=60) | 5,458 IPs from cache |

## Deduplication & Source Overlap

| Metric | Value |
|--------|-------|
| Unique to single source | 62,941 |
| Found in multiple sources | 50,736 |
| Max source overlap | 9 |
| Avg sources per IP | 1.86 |

### Per-Source Contribution

| Source | Unique | Shared | Unique % |
|--------|--------|--------|----------|
| RTBH (Turkiye) | 37,423 | 26,827 | 58.2% |
| SGB (Turkiye) | 9,636 | 364 | 96.4% |
| Stamparm IPsum | 7,071 | 29,425 | 19.4% |
| CINS Army | 4,160 | 10,840 | 27.7% |
| Spamhaus DROP | 1,687 | 0 | 100.0% |
| AbuseIPDB | 1,490 | 8,510 | 14.9% |
| GreenSnow | 458 | 5,000 | 8.4% |
| Tor Exit Nodes | 407 | 808 | 33.5% |
| AlienVault OTX | 351 | 66 | 84.2% |
| Spamhaus DROPv6 | 91 | 0 | 100.0% |
| BinaryDefense | 84 | 723 | 10.4% |
| Blocklist.de (all) | 65 | 28,432 | 0.2% |
| Emerging Threats | 10 | 460 | 2.1% |
| Blocklist.de (strongips) | 6 | 273 | 2.2% |
| Blocklist.de (mail) | 1 | 13,783 | 0.0% |
| Blocklist.de (bots) | 1 | 6,857 | 0.0% |
| Blocklist.de (ssh) | 0 | 4,955 | 0.0% |
| Blocklist.de (apache) | 0 | 9,987 | 0.0% |
| Blocklist.de (bruteforcelogin) | 0 | 1,619 | 0.0% |

### Top Source Pair Overlaps

| Pair | Shared IPs |
|------|-----------|
| Stamparm IPsum & RTBH (Turkiye) | 20,798 |
| Blocklist.de (all) & Blocklist.de (mail) | 13,768 |
| Blocklist.de (all) & RTBH (Turkiye) | 11,060 |
| Blocklist.de (all) & Blocklist.de (apache) | 9,987 |
| Blocklist.de (all) & Stamparm IPsum | 9,957 |
| CINS Army & Stamparm IPsum | 9,759 |
| Blocklist.de (mail) & Blocklist.de (apache) | 7,711 |
| Stamparm IPsum & AbuseIPDB | 7,669 |
| Blocklist.de (all) & Blocklist.de (bots) | 6,857 |
| RTBH (Turkiye) & AbuseIPDB | 6,409 |

## Consecutively Failing Sources

| Source | Failures | Last Failure | Reason |
|--------|----------|-------------|--------|
| GreenSnow | 1 | 2026-10-23 | ReadTimeout: HTTPSConnectionPool(host='blocklist.greensnow.c |

## All Sources

| Source | IPs | Status |
|--------|-----|--------|
| RTBH (Turkiye) | 64,250 | OK |
| Stamparm IPsum | 36,496 | OK |
| Blocklist.de (all) | 28,497 | OK |
| CINS Army | 15,000 | OK |
| Blocklist.de (mail) | 13,784 | OK |
| AbuseIPDB | 10,000 | OK |
| SGB (Turkiye) | 10,000 | OK |
| Blocklist.de (apache) | 9,987 | OK |
| Blocklist.de (bots) | 6,858 | OK |
| GreenSnow | 5,458 | CACHED |
| Blocklist.de (ssh) | 4,955 | OK |
| Spamhaus DROP | 1,687 | OK |
| Blocklist.de (bruteforcelogin) | 1,619 | OK |
| Tor Exit Nodes | 1,215 | OK |
| BinaryDefense | 807 | OK |
| Emerging Threats | 470 | OK |
| AlienVault OTX | 417 | OK |
| Blocklist.de (strongips) | 279 | OK |
| Spamhaus DROPv6 | 91 | OK |
