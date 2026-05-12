# IP Blacklist Aggregator - Health Report

**Date:** 2026-05-12T20:50:09.338278+00:00
**Duration:** 193.34s
**Successful:** 19/20

## Failed Sources This Run

| Source | Error | Cached |
|--------|------|--------|
| SGB (Turkiye) | ConnectTimeout: HTTPSConnectionPool(host='siberguvenlik.gov.tr', port=443): Max retries exceeded with url: /api/address/index?type=ip&page=1 (Caused by ConnectTimeoutError(<HTTPSConnection(host='siber | No cache |

## Deduplication & Source Overlap

| Metric | Value |
|--------|-------|
| Unique to single source | 131,626 |
| Found in multiple sources | 47,209 |
| Max source overlap | 9 |
| Avg sources per IP | 1.54 |

### Per-Source Contribution

| Source | Unique | Shared | Unique % |
|--------|--------|--------|----------|
| DShield | 91,934 | 15,841 | 85.3% |
| RTBH (Turkiye) | 23,308 | 17,955 | 56.5% |
| Stamparm IPsum | 6,518 | 29,328 | 18.2% |
| CINS Army | 5,262 | 9,738 | 35.1% |
| Spamhaus DROP | 1,611 | 0 | 100.0% |
| GreenSnow | 1,008 | 3,215 | 23.9% |
| AbuseIPDB | 791 | 9,209 | 7.9% |
| BinaryDefense | 612 | 1,321 | 31.7% |
| AlienVault OTX | 212 | 2 | 99.1% |
| Blocklist.de (all) | 176 | 23,428 | 0.7% |
| Spamhaus DROPv6 | 94 | 0 | 100.0% |
| Blocklist.de (strongips) | 52 | 273 | 16.0% |
| Blocklist.de (mail) | 39 | 13,954 | 0.3% |
| Emerging Threats | 7 | 409 | 1.7% |
| Tor Exit Nodes | 2 | 1,349 | 0.1% |
| Blocklist.de (ssh) | 0 | 4,794 | 0.0% |
| Blocklist.de (apache) | 0 | 9,420 | 0.0% |
| Blocklist.de (bots) | 0 | 2,856 | 0.0% |
| Blocklist.de (bruteforcelogin) | 0 | 1,243 | 0.0% |
| SGB (Turkiye) | 0 | 0 | N/A |

### Top Source Pair Overlaps

| Pair | Shared IPs |
|------|-----------|
| Stamparm IPsum & RTBH (Turkiye) | 15,890 |
| DShield & Stamparm IPsum | 14,261 |
| Blocklist.de (all) & Blocklist.de (mail) | 13,945 |
| Blocklist.de (all) & Blocklist.de (apache) | 9,420 |
| DShield & RTBH (Turkiye) | 8,878 |
| CINS Army & Stamparm IPsum | 8,612 |
| Blocklist.de (all) & Stamparm IPsum | 8,401 |
| Stamparm IPsum & AbuseIPDB | 8,028 |
| Blocklist.de (mail) & Blocklist.de (apache) | 7,967 |
| RTBH (Turkiye) & AbuseIPDB | 5,177 |

## 1 Sources Stale (30+ days)

| Source | Last Success | Consecutive Failures |
|--------|-------------|---------------------|
| SGB (Turkiye) | Never | 1 |

## Consecutively Failing Sources

| Source | Failures | Last Failure | Reason |
|--------|----------|-------------|--------|
| SGB (Turkiye) | 1 | 2026-05-12 | ConnectTimeout: HTTPSConnectionPool(host='siberguvenlik.gov. |

## All Sources

| Source | IPs | Status |
|--------|-----|--------|
| DShield | 107,775 | OK |
| RTBH (Turkiye) | 41,263 | OK |
| Stamparm IPsum | 35,846 | OK |
| Blocklist.de (all) | 23,604 | OK |
| CINS Army | 15,000 | OK |
| Blocklist.de (mail) | 13,993 | OK |
| AbuseIPDB | 10,000 | OK |
| Blocklist.de (apache) | 9,420 | OK |
| Blocklist.de (ssh) | 4,794 | OK |
| GreenSnow | 4,223 | OK |
| Blocklist.de (bots) | 2,856 | OK |
| BinaryDefense | 1,933 | OK |
| Spamhaus DROP | 1,611 | OK |
| Tor Exit Nodes | 1,351 | OK |
| Blocklist.de (bruteforcelogin) | 1,243 | OK |
| Emerging Threats | 416 | OK |
| Blocklist.de (strongips) | 325 | OK |
| AlienVault OTX | 214 | OK |
| Spamhaus DROPv6 | 94 | OK |
| SGB (Turkiye) | 0 | FAILED |
