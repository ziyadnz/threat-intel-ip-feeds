# IP Blacklist Aggregator - Health Report

**Date:** 2026-04-14T23:33:52.650325+00:00
**Duration:** 114.8s
**Successful:** 19/21

## Failed Sources This Run

| Source | Error |
|--------|------|
| USOM (Turkiye) | ClientResponseError: 429, message='<html>\r\n<head><title>429 Too Many Requests</title></head>\r\n<body>\r\n<center><h1>429 Too Many Requests</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n |

## Deduplication & Source Overlap

| Metric | Value |
|--------|-------|
| Unique to single source | 127,295 |
| Found in multiple sources | 37,969 |
| Max source overlap | 7 |
| Avg sources per IP | 1.41 |

### Per-Source Contribution

| Source | Unique | Shared | Unique % |
|--------|--------|--------|----------|
| DShield | 91,394 | 15,533 | 85.5% |
| RTBH (Turkiye) | 19,145 | 17,417 | 52.4% |
| Stamparm IPsum | 7,330 | 25,784 | 22.1% |
| CINS Army | 6,040 | 8,959 | 40.3% |
| Spamhaus DROP | 1,590 | 0 | 100.0% |
| BinaryDefense | 714 | 3,238 | 18.1% |
| GreenSnow | 677 | 3,640 | 15.7% |
| AlienVault OTX | 257 | 0 | 100.0% |
| Spamhaus DROPv6 | 96 | 0 | 100.0% |
| Blocklist.de (all) | 30 | 10,507 | 0.3% |
| Blocklist.de (ssh) | 7 | 786 | 0.9% |
| Blocklist.de (strongips) | 6 | 257 | 2.3% |
| Tor Exit Nodes | 6 | 1,299 | 0.5% |
| Emerging Threats | 2 | 385 | 0.5% |
| Blocklist.de (bruteforcelogin) | 1 | 349 | 0.3% |
| Feodo Tracker | 0 | 1 | 0.0% |
| Blocklist.de (mail) | 0 | 8,970 | 0.0% |
| Blocklist.de (apache) | 0 | 8,461 | 0.0% |
| Blocklist.de (bots) | 0 | 242 | 0.0% |
| USOM (Turkiye) | 0 | 0 | N/A |
| AbuseIPDB | 0 | 0 | N/A |

### Top Source Pair Overlaps

| Pair | Shared IPs |
|------|-----------|
| Stamparm IPsum & RTBH (Turkiye) | 15,827 |
| DShield & Stamparm IPsum | 13,951 |
| DShield & RTBH (Turkiye) | 9,358 |
| Blocklist.de (all) & Blocklist.de (mail) | 8,970 |
| Blocklist.de (all) & Blocklist.de (apache) | 8,461 |
| CINS Army & Stamparm IPsum | 7,997 |
| Blocklist.de (mail) & Blocklist.de (apache) | 7,967 |
| CINS Army & RTBH (Turkiye) | 4,981 |
| DShield & CINS Army | 3,669 |
| GreenSnow & Stamparm IPsum | 3,404 |

## 1 Sources Stale (30+ days)

| Source | Last Success | Consecutive Failures |
|--------|-------------|---------------------|
| AbuseIPDB | Never | 0 |

## Consecutively Failing Sources

| Source | Failures | Last Failure | Reason |
|--------|----------|-------------|--------|
| USOM (Turkiye) | 3 | 2026-04-14 | ClientResponseError: 429, message='<html>\r\n<head><title>42 |

## All Sources

| Source | IPs | Status |
|--------|-----|--------|
| DShield | 106,927 | OK |
| RTBH (Turkiye) | 36,562 | OK |
| Stamparm IPsum | 33,114 | OK |
| CINS Army | 14,999 | OK |
| Blocklist.de (all) | 10,537 | OK |
| Blocklist.de (mail) | 8,970 | OK |
| Blocklist.de (apache) | 8,461 | OK |
| GreenSnow | 4,317 | OK |
| BinaryDefense | 3,952 | OK |
| Spamhaus DROP | 1,590 | OK |
| Tor Exit Nodes | 1,305 | OK |
| Blocklist.de (ssh) | 793 | OK |
| Emerging Threats | 387 | OK |
| Blocklist.de (bruteforcelogin) | 350 | OK |
| Blocklist.de (strongips) | 263 | OK |
| AlienVault OTX | 257 | OK |
| Blocklist.de (bots) | 242 | OK |
| Spamhaus DROPv6 | 96 | OK |
| Feodo Tracker | 1 | OK |
| USOM (Turkiye) | 0 | FAILED |
| AbuseIPDB | 0 | EMPTY |
