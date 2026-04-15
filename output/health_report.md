# IP Blacklist Aggregator - Health Report

**Date:** 2026-04-15T01:17:03.112955+00:00
**Duration:** 106.44s
**Successful:** 19/21

## Failed Sources This Run

| Source | Error |
|--------|------|
| USOM (Turkiye) | ClientResponseError: 429, message='<html>\r\n<head><title>429 Too Many Requests</title></head>\r\n<body>\r\n<center><h1>429 Too Many Requests</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n |

## Deduplication & Source Overlap

| Metric | Value |
|--------|-------|
| Unique to single source | 58,028 |
| Found in multiple sources | 36,747 |
| Max source overlap | 7 |
| Avg sources per IP | 1.68 |

### Per-Source Contribution

| Source | Unique | Shared | Unique % |
|--------|--------|--------|----------|
| DShield | 23,547 | 9,928 | 70.3% |
| RTBH (Turkiye) | 19,760 | 16,946 | 53.8% |
| Stamparm IPsum | 6,719 | 25,954 | 20.6% |
| CINS Army | 3,998 | 11,002 | 26.7% |
| Spamhaus DROP | 1,590 | 0 | 100.0% |
| BinaryDefense | 797 | 3,384 | 19.1% |
| Tor Exit Nodes | 649 | 655 | 49.8% |
| GreenSnow | 580 | 3,768 | 13.3% |
| AlienVault OTX | 257 | 0 | 100.0% |
| Spamhaus DROPv6 | 96 | 0 | 100.0% |
| Blocklist.de (all) | 22 | 10,522 | 0.2% |
| Blocklist.de (strongips) | 7 | 255 | 2.7% |
| Blocklist.de (ssh) | 3 | 770 | 0.4% |
| Emerging Threats | 3 | 384 | 0.8% |
| Feodo Tracker | 0 | 1 | 0.0% |
| Blocklist.de (mail) | 0 | 8,976 | 0.0% |
| Blocklist.de (apache) | 0 | 8,474 | 0.0% |
| Blocklist.de (bots) | 0 | 245 | 0.0% |
| Blocklist.de (bruteforcelogin) | 0 | 364 | 0.0% |
| USOM (Turkiye) | 0 | 0 | N/A |
| AbuseIPDB | 0 | 0 | N/A |

### Top Source Pair Overlaps

| Pair | Shared IPs |
|------|-----------|
| Stamparm IPsum & RTBH (Turkiye) | 15,727 |
| CINS Army & Stamparm IPsum | 10,051 |
| DShield & Stamparm IPsum | 9,535 |
| Blocklist.de (all) & Blocklist.de (mail) | 8,976 |
| Blocklist.de (all) & Blocklist.de (apache) | 8,473 |
| Blocklist.de (mail) & Blocklist.de (apache) | 7,967 |
| CINS Army & RTBH (Turkiye) | 6,371 |
| DShield & RTBH (Turkiye) | 6,044 |
| GreenSnow & Stamparm IPsum | 3,593 |
| BinaryDefense & Stamparm IPsum | 3,293 |

## 1 Sources Stale (30+ days)

| Source | Last Success | Consecutive Failures |
|--------|-------------|---------------------|
| AbuseIPDB | Never | 0 |

## Consecutively Failing Sources

| Source | Failures | Last Failure | Reason |
|--------|----------|-------------|--------|
| USOM (Turkiye) | 4 | 2026-04-15 | ClientResponseError: 429, message='<html>\r\n<head><title>42 |

## All Sources

| Source | IPs | Status |
|--------|-----|--------|
| RTBH (Turkiye) | 36,706 | OK |
| DShield | 33,475 | OK |
| Stamparm IPsum | 32,673 | OK |
| CINS Army | 15,000 | OK |
| Blocklist.de (all) | 10,544 | OK |
| Blocklist.de (mail) | 8,976 | OK |
| Blocklist.de (apache) | 8,474 | OK |
| GreenSnow | 4,348 | OK |
| BinaryDefense | 4,181 | OK |
| Spamhaus DROP | 1,590 | OK |
| Tor Exit Nodes | 1,304 | OK |
| Blocklist.de (ssh) | 773 | OK |
| Emerging Threats | 387 | OK |
| Blocklist.de (bruteforcelogin) | 364 | OK |
| Blocklist.de (strongips) | 262 | OK |
| AlienVault OTX | 257 | OK |
| Blocklist.de (bots) | 245 | OK |
| Spamhaus DROPv6 | 96 | OK |
| Feodo Tracker | 1 | OK |
| USOM (Turkiye) | 0 | FAILED |
| AbuseIPDB | 0 | EMPTY |
