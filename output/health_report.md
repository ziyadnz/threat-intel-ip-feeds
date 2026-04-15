# IP Blacklist Aggregator - Health Report

**Date:** 2026-04-15T08:20:55.076760+00:00
**Duration:** 110.11s
**Successful:** 19/21

## Failed Sources This Run

| Source | Error |
|--------|------|
| USOM (Turkiye) | ClientResponseError: 429, message='<html>\r\n<head><title>429 Too Many Requests</title></head>\r\n<body>\r\n<center><h1>429 Too Many Requests</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n |

## Deduplication & Source Overlap

| Metric | Value |
|--------|-------|
| Unique to single source | 115,793 |
| Found in multiple sources | 37,619 |
| Max source overlap | 7 |
| Avg sources per IP | 1.44 |

### Per-Source Contribution

| Source | Unique | Shared | Unique % |
|--------|--------|--------|----------|
| DShield | 80,768 | 13,499 | 85.7% |
| RTBH (Turkiye) | 20,101 | 17,244 | 53.8% |
| Stamparm IPsum | 6,921 | 25,752 | 21.2% |
| CINS Army | 4,626 | 10,374 | 30.8% |
| Spamhaus DROP | 1,590 | 0 | 100.0% |
| BinaryDefense | 792 | 3,389 | 18.9% |
| GreenSnow | 603 | 3,695 | 14.0% |
| AlienVault OTX | 257 | 0 | 100.0% |
| Spamhaus DROPv6 | 96 | 0 | 100.0% |
| Blocklist.de (all) | 26 | 10,521 | 0.2% |
| Blocklist.de (strongips) | 7 | 255 | 2.7% |
| Emerging Threats | 3 | 384 | 0.8% |
| Tor Exit Nodes | 2 | 1,302 | 0.2% |
| Blocklist.de (mail) | 1 | 9,033 | 0.0% |
| Feodo Tracker | 0 | 1 | 0.0% |
| Blocklist.de (ssh) | 0 | 750 | 0.0% |
| Blocklist.de (apache) | 0 | 8,444 | 0.0% |
| Blocklist.de (bots) | 0 | 241 | 0.0% |
| Blocklist.de (bruteforcelogin) | 0 | 334 | 0.0% |
| USOM (Turkiye) | 0 | 0 | N/A |
| AbuseIPDB | 0 | 0 | N/A |

### Top Source Pair Overlaps

| Pair | Shared IPs |
|------|-----------|
| Stamparm IPsum & RTBH (Turkiye) | 15,795 |
| DShield & Stamparm IPsum | 12,040 |
| CINS Army & Stamparm IPsum | 9,463 |
| Blocklist.de (all) & Blocklist.de (mail) | 9,033 |
| Blocklist.de (all) & Blocklist.de (apache) | 8,441 |
| Blocklist.de (mail) & Blocklist.de (apache) | 7,967 |
| DShield & RTBH (Turkiye) | 7,864 |
| CINS Army & RTBH (Turkiye) | 6,158 |
| GreenSnow & Stamparm IPsum | 3,512 |
| DShield & CINS Army | 3,355 |

## 1 Sources Stale (30+ days)

| Source | Last Success | Consecutive Failures |
|--------|-------------|---------------------|
| AbuseIPDB | Never | 0 |

## Consecutively Failing Sources

| Source | Failures | Last Failure | Reason |
|--------|----------|-------------|--------|
| USOM (Turkiye) | 7 | 2026-04-15 | ClientResponseError: 429, message='<html>\r\n<head><title>42 |

## All Sources

| Source | IPs | Status |
|--------|-----|--------|
| DShield | 94,267 | OK |
| RTBH (Turkiye) | 37,345 | OK |
| Stamparm IPsum | 32,673 | OK |
| CINS Army | 15,000 | OK |
| Blocklist.de (all) | 10,547 | OK |
| Blocklist.de (mail) | 9,034 | OK |
| Blocklist.de (apache) | 8,444 | OK |
| GreenSnow | 4,298 | OK |
| BinaryDefense | 4,181 | OK |
| Spamhaus DROP | 1,590 | OK |
| Tor Exit Nodes | 1,304 | OK |
| Blocklist.de (ssh) | 750 | OK |
| Emerging Threats | 387 | OK |
| Blocklist.de (bruteforcelogin) | 334 | OK |
| Blocklist.de (strongips) | 262 | OK |
| AlienVault OTX | 257 | OK |
| Blocklist.de (bots) | 241 | OK |
| Spamhaus DROPv6 | 96 | OK |
| Feodo Tracker | 1 | OK |
| USOM (Turkiye) | 0 | FAILED |
| AbuseIPDB | 0 | EMPTY |
