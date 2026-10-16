# IP Blacklist Aggregator - Health Report

**Date:** 2026-10-16T07:10:01.065319+00:00
**Duration:** 26.14s
**Successful:** 18/19

## Failed Sources This Run

| Source | Error | Cached |
|--------|------|--------|
| GreenSnow | HttpError: HTTP 503: <!DOCTYPE html>
<html style="height:100%">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
<title> 503 Service Unavailable
</title | 5,182 IPs from cache |

## Deduplication & Source Overlap

| Metric | Value |
|--------|-------|
| Unique to single source | 70,515 |
| Found in multiple sources | 47,977 |
| Max source overlap | 9 |
| Avg sources per IP | 1.79 |

### Per-Source Contribution

| Source | Unique | Shared | Unique % |
|--------|--------|--------|----------|
| RTBH (Turkiye) | 47,550 | 26,221 | 64.5% |
| SGB (Turkiye) | 9,631 | 369 | 96.3% |
| Stamparm IPsum | 5,825 | 28,146 | 17.1% |
| CINS Army | 3,228 | 11,772 | 21.5% |
| Spamhaus DROP | 1,689 | 0 | 100.0% |
| AbuseIPDB | 1,338 | 8,662 | 13.4% |
| Tor Exit Nodes | 410 | 804 | 33.8% |
| GreenSnow | 309 | 4,873 | 6.0% |
| AlienVault OTX | 268 | 75 | 78.1% |
| Spamhaus DROPv6 | 91 | 0 | 100.0% |
| BinaryDefense | 81 | 653 | 11.0% |
| Blocklist.de (all) | 41 | 25,111 | 0.2% |
| Blocklist.de (bots) | 17 | 5,458 | 0.3% |
| Emerging Threats | 16 | 501 | 3.1% |
| Blocklist.de (apache) | 7 | 9,633 | 0.1% |
| Blocklist.de (mail) | 6 | 13,194 | 0.0% |
| Blocklist.de (strongips) | 5 | 241 | 2.0% |
| Blocklist.de (ssh) | 3 | 4,267 | 0.1% |
| Blocklist.de (bruteforcelogin) | 0 | 1,259 | 0.0% |

### Top Source Pair Overlaps

| Pair | Shared IPs |
|------|-----------|
| Stamparm IPsum & RTBH (Turkiye) | 19,357 |
| Blocklist.de (all) & Blocklist.de (mail) | 13,144 |
| CINS Army & Stamparm IPsum | 10,686 |
| Blocklist.de (all) & RTBH (Turkiye) | 10,526 |
| Blocklist.de (all) & Blocklist.de (apache) | 9,629 |
| Blocklist.de (all) & Stamparm IPsum | 8,505 |
| Blocklist.de (mail) & Blocklist.de (apache) | 7,711 |
| Stamparm IPsum & AbuseIPDB | 7,619 |
| CINS Army & RTBH (Turkiye) | 6,580 |
| RTBH (Turkiye) & AbuseIPDB | 6,383 |

## Consecutively Failing Sources

| Source | Failures | Last Failure | Reason |
|--------|----------|-------------|--------|
| GreenSnow | 1 | 2026-10-16 | HttpError: HTTP 503: <!DOCTYPE html>
<html style="height:100 |

## All Sources

| Source | IPs | Status |
|--------|-----|--------|
| RTBH (Turkiye) | 73,771 | OK |
| Stamparm IPsum | 33,971 | OK |
| Blocklist.de (all) | 25,152 | OK |
| CINS Army | 15,000 | OK |
| Blocklist.de (mail) | 13,200 | OK |
| AbuseIPDB | 10,000 | OK |
| SGB (Turkiye) | 10,000 | OK |
| Blocklist.de (apache) | 9,640 | OK |
| Blocklist.de (bots) | 5,475 | OK |
| GreenSnow | 5,182 | CACHED |
| Blocklist.de (ssh) | 4,270 | OK |
| Spamhaus DROP | 1,689 | OK |
| Blocklist.de (bruteforcelogin) | 1,259 | OK |
| Tor Exit Nodes | 1,214 | OK |
| BinaryDefense | 734 | OK |
| Emerging Threats | 517 | OK |
| AlienVault OTX | 343 | OK |
| Blocklist.de (strongips) | 246 | OK |
| Spamhaus DROPv6 | 91 | OK |
