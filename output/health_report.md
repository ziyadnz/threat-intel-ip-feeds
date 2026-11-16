# IP Blacklist Aggregator - Health Report

**Date:** 2026-11-16T20:29:25.742311+00:00
**Duration:** 166.41s
**Successful:** 19/19
**Fresh Fetches:** 18
**Sources Using Cache:** 1

## Cache Usage

Cache reuse is separated from a fresh successful fetch. Duration includes requests, retries, and waits.

| Source | Reason | Cache Observed At (UTC) | Cache Age at Run Start | Fetch Duration |
|--------|--------|-------------------------|------------------------|----------------|
| AbuseIPDB | Scheduled cache reuse: 4h refresh interval; next fetch due 2026-11-16T23:57:48.844670+00:00 | 2026-11-16T19:57:48.844670+00:00 | 0h 31m 36s | 0.06s |

## Deduplication & Source Overlap

| Metric | Value |
|--------|-------|
| Unique to single source | 57,178 |
| Found in multiple sources | 43,166 |
| Max source overlap | 8 |
| Avg sources per IP | 1.79 |

### Per-Source Contribution

| Source | Unique | Shared | Unique % |
|--------|--------|--------|----------|
| RTBH (Turkiye) | 25,957 | 20,706 | 55.6% |
| Stamparm IPsum | 11,536 | 26,552 | 30.3% |
| SGB (Turkiye) | 9,622 | 378 | 96.2% |
| CINS Army | 5,593 | 9,407 | 37.3% |
| Spamhaus DROP | 1,735 | 0 | 100.0% |
| AbuseIPDB | 1,680 | 8,320 | 16.8% |
| Tor Exit Nodes | 318 | 950 | 25.1% |
| AlienVault OTX | 280 | 86 | 76.5% |
| GreenSnow | 145 | 934 | 13.4% |
| BinaryDefense | 104 | 995 | 9.5% |
| Spamhaus DROPv6 | 90 | 0 | 100.0% |
| Emerging Threats | 57 | 527 | 9.8% |
| Blocklist.de (all) | 46 | 22,746 | 0.2% |
| Blocklist.de (strongips) | 15 | 271 | 5.2% |
| Blocklist.de (ssh) | 0 | 4,360 | 0.0% |
| Blocklist.de (mail) | 0 | 13,291 | 0.0% |
| Blocklist.de (apache) | 0 | 9,076 | 0.0% |
| Blocklist.de (bots) | 0 | 3,249 | 0.0% |
| Blocklist.de (bruteforcelogin) | 0 | 719 | 0.0% |

### Top Source Pair Overlaps

| Pair | Shared IPs |
|------|-----------|
| Stamparm IPsum & RTBH (Turkiye) | 16,758 |
| Blocklist.de (all) & Blocklist.de (mail) | 13,291 |
| Blocklist.de (all) & Blocklist.de (apache) | 9,076 |
| CINS Army & Stamparm IPsum | 8,785 |
| Blocklist.de (all) & RTBH (Turkiye) | 8,678 |
| Blocklist.de (mail) & Blocklist.de (apache) | 7,711 |
| Blocklist.de (all) & Stamparm IPsum | 7,675 |
| Stamparm IPsum & AbuseIPDB | 7,277 |
| RTBH (Turkiye) & AbuseIPDB | 5,300 |
| Blocklist.de (all) & Blocklist.de (ssh) | 4,354 |

## All Sources

| Source | IPs | Status | Fetch Duration | Details |
|--------|-----|--------|----------------|---------|
| RTBH (Turkiye) | 46,663 | OK | 2.06s | Fresh fetch |
| Stamparm IPsum | 38,088 | OK | 0.98s | Fresh fetch |
| Blocklist.de (all) | 22,792 | OK | 1.19s | Fresh fetch |
| CINS Army | 15,000 | OK | 0.85s | Fresh fetch |
| Blocklist.de (mail) | 13,291 | OK | 0.86s | Fresh fetch |
| AbuseIPDB | 10,000 | CACHED | 0.06s | Scheduled cache reuse: 4h refresh interval; next fetch due 2026-11-16T23:57:48.844670+00:00 |
| SGB (Turkiye) | 10,000 | OK | 4.88s | Fresh fetch |
| Blocklist.de (apache) | 9,076 | OK | 0.85s | Fresh fetch |
| Blocklist.de (ssh) | 4,360 | OK | 0.78s | Fresh fetch |
| Blocklist.de (bots) | 3,249 | OK | 0.64s | Fresh fetch |
| Spamhaus DROP | 1,735 | OK | 0.28s | Fresh fetch |
| Tor Exit Nodes | 1,268 | OK | 0.62s | Fresh fetch |
| BinaryDefense | 1,099 | OK | 0.63s | Fresh fetch |
| GreenSnow | 1,079 | OK | 0.74s | Fresh fetch |
| Blocklist.de (bruteforcelogin) | 719 | OK | 0.41s | Fresh fetch |
| Emerging Threats | 584 | OK | 0.51s | Fresh fetch |
| AlienVault OTX | 366 | OK | 164.44s | Fresh fetch |
| Blocklist.de (strongips) | 286 | OK | 0.39s | Fresh fetch |
| Spamhaus DROPv6 | 90 | OK | 0.28s | Fresh fetch |

## All sources healthy.
