# IP Blacklist Aggregator - Health Report

**Date:** 2026-04-14T22:35:23.501377+00:00
**Duration:** 111.62s
**Successful:** 19/21

## Failed Sources This Run

| Source | Error |
|--------|------|
| USOM (Turkiye) | ClientResponseError: 429, message='<html>\r\n<head><title>429 Too Many Requests</title></head>\r\n<body>\r\n<center><h1>429 Too Many Requests</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n |

## Deduplication & Source Overlap

| Metric | Value |
|--------|-------|
| Unique to single source | 127,124 |
| Found in multiple sources | 37,919 |
| Max source overlap | 7 |
| Avg sources per IP | 1.41 |

### Per-Source Contribution

| Source | Unique | Shared | Unique % |
|--------|--------|--------|----------|
| DShield | 91,384 | 15,543 | 85.5% |
| RTBH (Turkiye) | 19,114 | 17,414 | 52.3% |
| Stamparm IPsum | 7,398 | 25,716 | 22.3% |
| CINS Army | 5,945 | 9,054 | 39.6% |
| Spamhaus DROP | 1,590 | 0 | 100.0% |
| BinaryDefense | 717 | 3,235 | 18.1% |
| GreenSnow | 579 | 3,221 | 15.2% |
| AlienVault OTX | 257 | 0 | 100.0% |
| Spamhaus DROPv6 | 96 | 0 | 100.0% |
| Blocklist.de (all) | 29 | 10,539 | 0.3% |
| Blocklist.de (strongips) | 6 | 257 | 2.3% |
| Tor Exit Nodes | 6 | 1,299 | 0.5% |
| Emerging Threats | 2 | 385 | 0.5% |
| Blocklist.de (apache) | 1 | 8,466 | 0.0% |
| Feodo Tracker | 0 | 1 | 0.0% |
| Blocklist.de (ssh) | 0 | 799 | 0.0% |
| Blocklist.de (mail) | 0 | 8,979 | 0.0% |
| Blocklist.de (bots) | 0 | 239 | 0.0% |
| Blocklist.de (bruteforcelogin) | 0 | 351 | 0.0% |
| USOM (Turkiye) | 0 | 0 | N/A |
| AbuseIPDB | 0 | 0 | N/A |

### Top Source Pair Overlaps

| Pair | Shared IPs |
|------|-----------|
| Stamparm IPsum & RTBH (Turkiye) | 15,818 |
| DShield & Stamparm IPsum | 13,951 |
| DShield & RTBH (Turkiye) | 9,354 |
| Blocklist.de (all) & Blocklist.de (mail) | 8,979 |
| Blocklist.de (all) & Blocklist.de (apache) | 8,466 |
| CINS Army & Stamparm IPsum | 8,043 |
| Blocklist.de (mail) & Blocklist.de (apache) | 7,967 |
| CINS Army & RTBH (Turkiye) | 5,051 |
| DShield & CINS Army | 3,703 |
| BinaryDefense & Stamparm IPsum | 3,153 |

## 1 Sources Stale (30+ days)

| Source | Last Success | Consecutive Failures |
|--------|-------------|---------------------|
| AbuseIPDB | Never | 0 |

## Consecutively Failing Sources

| Source | Failures | Last Failure | Reason |
|--------|----------|-------------|--------|
| USOM (Turkiye) | 2 | 2026-04-14 | ClientResponseError: 429, message='<html>\r\n<head><title>42 |

## All Sources

| Source | IPs | Status |
|--------|-----|--------|
| DShield | 106,927 | OK |
| RTBH (Turkiye) | 36,528 | OK |
| Stamparm IPsum | 33,114 | OK |
| CINS Army | 14,999 | OK |
| Blocklist.de (all) | 10,568 | OK |
| Blocklist.de (mail) | 8,979 | OK |
| Blocklist.de (apache) | 8,467 | OK |
| BinaryDefense | 3,952 | OK |
| GreenSnow | 3,800 | OK |
| Spamhaus DROP | 1,590 | OK |
| Tor Exit Nodes | 1,305 | OK |
| Blocklist.de (ssh) | 799 | OK |
| Emerging Threats | 387 | OK |
| Blocklist.de (bruteforcelogin) | 351 | OK |
| Blocklist.de (strongips) | 263 | OK |
| AlienVault OTX | 257 | OK |
| Blocklist.de (bots) | 239 | OK |
| Spamhaus DROPv6 | 96 | OK |
| Feodo Tracker | 1 | OK |
| USOM (Turkiye) | 0 | FAILED |
| AbuseIPDB | 0 | EMPTY |
