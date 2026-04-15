# IP Blacklist Aggregator - Health Report

**Date:** 2026-04-15T04:35:57.584312+00:00
**Duration:** 140.88s
**Successful:** 19/21

## Failed Sources This Run

| Source | Error |
|--------|------|
| USOM (Turkiye) | ClientResponseError: 429, message='<html>\r\n<head><title>429 Too Many Requests</title></head>\r\n<body>\r\n<center><h1>429 Too Many Requests</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n |

## Deduplication & Source Overlap

| Metric | Value |
|--------|-------|
| Unique to single source | 115,109 |
| Found in multiple sources | 37,799 |
| Max source overlap | 7 |
| Avg sources per IP | 1.44 |

### Per-Source Contribution

| Source | Unique | Shared | Unique % |
|--------|--------|--------|----------|
| DShield | 80,770 | 13,497 | 85.7% |
| RTBH (Turkiye) | 19,667 | 17,292 | 53.2% |
| Stamparm IPsum | 6,739 | 25,934 | 20.6% |
| CINS Army | 4,577 | 10,423 | 30.5% |
| Spamhaus DROP | 1,590 | 0 | 100.0% |
| BinaryDefense | 793 | 3,388 | 19.0% |
| GreenSnow | 586 | 3,754 | 13.5% |
| AlienVault OTX | 257 | 0 | 100.0% |
| Spamhaus DROPv6 | 96 | 0 | 100.0% |
| Blocklist.de (all) | 23 | 10,480 | 0.2% |
| Blocklist.de (strongips) | 7 | 255 | 2.7% |
| Emerging Threats | 3 | 384 | 0.8% |
| Tor Exit Nodes | 1 | 1,302 | 0.1% |
| Feodo Tracker | 0 | 1 | 0.0% |
| Blocklist.de (ssh) | 0 | 725 | 0.0% |
| Blocklist.de (mail) | 0 | 8,999 | 0.0% |
| Blocklist.de (apache) | 0 | 8,461 | 0.0% |
| Blocklist.de (bots) | 0 | 238 | 0.0% |
| Blocklist.de (bruteforcelogin) | 0 | 352 | 0.0% |
| USOM (Turkiye) | 0 | 0 | N/A |
| AbuseIPDB | 0 | 0 | N/A |

### Top Source Pair Overlaps

| Pair | Shared IPs |
|------|-----------|
| Stamparm IPsum & RTBH (Turkiye) | 15,764 |
| DShield & Stamparm IPsum | 12,040 |
| CINS Army & Stamparm IPsum | 9,422 |
| Blocklist.de (all) & Blocklist.de (mail) | 8,999 |
| Blocklist.de (all) & Blocklist.de (apache) | 8,461 |
| Blocklist.de (mail) & Blocklist.de (apache) | 7,967 |
| DShield & RTBH (Turkiye) | 7,842 |
| CINS Army & RTBH (Turkiye) | 6,017 |
| GreenSnow & Stamparm IPsum | 3,572 |
| BinaryDefense & Stamparm IPsum | 3,293 |

## 1 Sources Stale (30+ days)

| Source | Last Success | Consecutive Failures |
|--------|-------------|---------------------|
| AbuseIPDB | Never | 0 |

## Consecutively Failing Sources

| Source | Failures | Last Failure | Reason |
|--------|----------|-------------|--------|
| USOM (Turkiye) | 5 | 2026-04-15 | ClientResponseError: 429, message='<html>\r\n<head><title>42 |

## All Sources

| Source | IPs | Status |
|--------|-----|--------|
| DShield | 94,267 | OK |
| RTBH (Turkiye) | 36,959 | OK |
| Stamparm IPsum | 32,673 | OK |
| CINS Army | 15,000 | OK |
| Blocklist.de (all) | 10,503 | OK |
| Blocklist.de (mail) | 8,999 | OK |
| Blocklist.de (apache) | 8,461 | OK |
| GreenSnow | 4,340 | OK |
| BinaryDefense | 4,181 | OK |
| Spamhaus DROP | 1,590 | OK |
| Tor Exit Nodes | 1,303 | OK |
| Blocklist.de (ssh) | 725 | OK |
| Emerging Threats | 387 | OK |
| Blocklist.de (bruteforcelogin) | 352 | OK |
| Blocklist.de (strongips) | 262 | OK |
| AlienVault OTX | 257 | OK |
| Blocklist.de (bots) | 238 | OK |
| Spamhaus DROPv6 | 96 | OK |
| Feodo Tracker | 1 | OK |
| USOM (Turkiye) | 0 | FAILED |
| AbuseIPDB | 0 | EMPTY |
