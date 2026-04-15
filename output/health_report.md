# IP Blacklist Aggregator - Health Report

**Date:** 2026-04-15T06:26:01.046492+00:00
**Duration:** 173.9s
**Successful:** 19/21

## Failed Sources This Run

| Source | Error |
|--------|------|
| USOM (Turkiye) | ClientResponseError: 429, message='<html>\r\n<head><title>429 Too Many Requests</title></head>\r\n<body>\r\n<center><h1>429 Too Many Requests</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n |

## Deduplication & Source Overlap

| Metric | Value |
|--------|-------|
| Unique to single source | 115,120 |
| Found in multiple sources | 37,810 |
| Max source overlap | 7 |
| Avg sources per IP | 1.44 |

### Per-Source Contribution

| Source | Unique | Shared | Unique % |
|--------|--------|--------|----------|
| DShield | 80,783 | 13,484 | 85.7% |
| RTBH (Turkiye) | 19,876 | 17,254 | 53.5% |
| Stamparm IPsum | 6,715 | 25,958 | 20.6% |
| CINS Army | 4,492 | 10,508 | 29.9% |
| Spamhaus DROP | 1,590 | 0 | 100.0% |
| BinaryDefense | 792 | 3,389 | 18.9% |
| GreenSnow | 595 | 3,721 | 13.8% |
| AlienVault OTX | 143 | 0 | 100.0% |
| Spamhaus DROPv6 | 96 | 0 | 100.0% |
| Blocklist.de (all) | 23 | 10,507 | 0.2% |
| Blocklist.de (strongips) | 7 | 255 | 2.7% |
| Emerging Threats | 3 | 384 | 0.8% |
| Blocklist.de (mail) | 2 | 9,039 | 0.0% |
| Blocklist.de (apache) | 1 | 8,441 | 0.0% |
| Blocklist.de (bots) | 1 | 229 | 0.4% |
| Tor Exit Nodes | 1 | 1,302 | 0.1% |
| Feodo Tracker | 0 | 1 | 0.0% |
| Blocklist.de (ssh) | 0 | 743 | 0.0% |
| Blocklist.de (bruteforcelogin) | 0 | 336 | 0.0% |
| USOM (Turkiye) | 0 | 0 | N/A |
| AbuseIPDB | 0 | 0 | N/A |

### Top Source Pair Overlaps

| Pair | Shared IPs |
|------|-----------|
| Stamparm IPsum & RTBH (Turkiye) | 15,778 |
| DShield & Stamparm IPsum | 12,040 |
| CINS Army & Stamparm IPsum | 9,586 |
| Blocklist.de (all) & Blocklist.de (mail) | 9,039 |
| Blocklist.de (all) & Blocklist.de (apache) | 8,440 |
| Blocklist.de (mail) & Blocklist.de (apache) | 7,967 |
| DShield & RTBH (Turkiye) | 7,850 |
| CINS Army & RTBH (Turkiye) | 6,061 |
| GreenSnow & Stamparm IPsum | 3,538 |
| BinaryDefense & Stamparm IPsum | 3,293 |

## 1 Sources Stale (30+ days)

| Source | Last Success | Consecutive Failures |
|--------|-------------|---------------------|
| AbuseIPDB | Never | 0 |

## Consecutively Failing Sources

| Source | Failures | Last Failure | Reason |
|--------|----------|-------------|--------|
| USOM (Turkiye) | 6 | 2026-04-15 | ClientResponseError: 429, message='<html>\r\n<head><title>42 |

## All Sources

| Source | IPs | Status |
|--------|-----|--------|
| DShield | 94,267 | OK |
| RTBH (Turkiye) | 37,130 | OK |
| Stamparm IPsum | 32,673 | OK |
| CINS Army | 15,000 | OK |
| Blocklist.de (all) | 10,530 | OK |
| Blocklist.de (mail) | 9,041 | OK |
| Blocklist.de (apache) | 8,442 | OK |
| GreenSnow | 4,316 | OK |
| BinaryDefense | 4,181 | OK |
| Spamhaus DROP | 1,590 | OK |
| Tor Exit Nodes | 1,303 | OK |
| Blocklist.de (ssh) | 743 | OK |
| Emerging Threats | 387 | OK |
| Blocklist.de (bruteforcelogin) | 336 | OK |
| Blocklist.de (strongips) | 262 | OK |
| Blocklist.de (bots) | 230 | OK |
| AlienVault OTX | 143 | OK |
| Spamhaus DROPv6 | 96 | OK |
| Feodo Tracker | 1 | OK |
| USOM (Turkiye) | 0 | FAILED |
| AbuseIPDB | 0 | EMPTY |
