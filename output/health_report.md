# IP Blacklist Aggregator - Health Report

**Date:** 2026-04-14T21:40:18.197889+00:00
**Duration:** 207.78s
**Successful:** 19/21

## Failed Sources This Run

| Source | Error |
|--------|------|
| USOM (Turkiye) | ClientResponseError: 429, message='<html>\r\n<head><title>429 Too Many Requests</title></head>\r\n<body>\r\n<center><h1>429 Too Many Requests</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n |

## Deduplication & Source Overlap

| Metric | Value |
|--------|-------|
| Unique to single source | 126,928 |
| Found in multiple sources | 37,898 |
| Max source overlap | 7 |
| Avg sources per IP | 1.41 |

### Per-Source Contribution

| Source | Unique | Shared | Unique % |
|--------|--------|--------|----------|
| DShield | 91,378 | 15,549 | 85.5% |
| RTBH (Turkiye) | 19,105 | 17,352 | 52.4% |
| Stamparm IPsum | 7,378 | 25,736 | 22.3% |
| CINS Army | 5,906 | 9,093 | 39.4% |
| Spamhaus DROP | 1,590 | 0 | 100.0% |
| BinaryDefense | 717 | 3,235 | 18.1% |
| GreenSnow | 577 | 3,241 | 15.1% |
| AlienVault OTX | 143 | 0 | 100.0% |
| Spamhaus DROPv6 | 96 | 0 | 100.0% |
| Blocklist.de (all) | 27 | 10,536 | 0.3% |
| Blocklist.de (strongips) | 6 | 257 | 2.3% |
| Tor Exit Nodes | 3 | 1,296 | 0.2% |
| Emerging Threats | 2 | 385 | 0.5% |
| Feodo Tracker | 0 | 1 | 0.0% |
| Blocklist.de (ssh) | 0 | 792 | 0.0% |
| Blocklist.de (mail) | 0 | 8,976 | 0.0% |
| Blocklist.de (apache) | 0 | 8,471 | 0.0% |
| Blocklist.de (bots) | 0 | 241 | 0.0% |
| Blocklist.de (bruteforcelogin) | 0 | 355 | 0.0% |
| USOM (Turkiye) | 0 | 0 | N/A |
| AbuseIPDB | 0 | 0 | N/A |

### Top Source Pair Overlaps

| Pair | Shared IPs |
|------|-----------|
| Stamparm IPsum & RTBH (Turkiye) | 15,803 |
| DShield & Stamparm IPsum | 13,951 |
| DShield & RTBH (Turkiye) | 9,348 |
| Blocklist.de (all) & Blocklist.de (mail) | 8,976 |
| Blocklist.de (all) & Blocklist.de (apache) | 8,471 |
| CINS Army & Stamparm IPsum | 8,110 |
| Blocklist.de (mail) & Blocklist.de (apache) | 7,967 |
| CINS Army & RTBH (Turkiye) | 5,055 |
| DShield & CINS Army | 3,785 |
| BinaryDefense & Stamparm IPsum | 3,153 |

## 1 Sources Stale (30+ days)

| Source | Last Success | Consecutive Failures |
|--------|-------------|---------------------|
| AbuseIPDB | Never | 0 |

## Consecutively Failing Sources

| Source | Failures | Last Failure | Reason |
|--------|----------|-------------|--------|
| USOM (Turkiye) | 1 | 2026-04-14 | ClientResponseError: 429, message='<html>\r\n<head><title>42 |

## All Sources

| Source | IPs | Status |
|--------|-----|--------|
| DShield | 106,927 | OK |
| RTBH (Turkiye) | 36,457 | OK |
| Stamparm IPsum | 33,114 | OK |
| CINS Army | 14,999 | OK |
| Blocklist.de (all) | 10,563 | OK |
| Blocklist.de (mail) | 8,976 | OK |
| Blocklist.de (apache) | 8,471 | OK |
| BinaryDefense | 3,952 | OK |
| GreenSnow | 3,818 | OK |
| Spamhaus DROP | 1,590 | OK |
| Tor Exit Nodes | 1,299 | OK |
| Blocklist.de (ssh) | 792 | OK |
| Emerging Threats | 387 | OK |
| Blocklist.de (bruteforcelogin) | 355 | OK |
| Blocklist.de (strongips) | 263 | OK |
| Blocklist.de (bots) | 241 | OK |
| AlienVault OTX | 143 | OK |
| Spamhaus DROPv6 | 96 | OK |
| Feodo Tracker | 1 | OK |
| USOM (Turkiye) | 0 | FAILED |
| AbuseIPDB | 0 | EMPTY |
