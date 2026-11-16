# Threat Intel IP Feeds

![Updated](https://img.shields.io/github/last-commit/ziyadnz/threat-intel-ip-feeds/main?label=last%20update)
![Build Status](https://img.shields.io/github/actions/workflow/status/ziyadnz/threat-intel-ip-feeds/update.yml?label=hourly%20run)
![License](https://img.shields.io/github/license/ziyadnz/threat-intel-ip-feeds)
![Stars](https://img.shields.io/github/stars/ziyadnz/threat-intel-ip-feeds?style=social)

**Hourly updated, firewall-ready IP blocklist aggregated from 18+ threat intelligence sources. ~120,000+ unique malicious IPs, deduplicated, validated, and ready to import.**

```
https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt
```
Copy the URL above into your firewall, SIEM, or any tool that accepts a plain-text IP blocklist. One IP/CIDR per line, no comments, no headers. Updated every hour.

---

## Quick Usage Examples

### FortiGate

> Full documentation: [FortiGate External Block List Policy Guide](https://docs.fortinet.com/document/fortigate/7.0.0/administration-guide/891236/external-blocklist-policy)

![FortiGate External Block List](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/resources/761d83e3-4a7b-11e9-94bf-00505692583a/images/d87a548c44fbe9ef14a6d01e377791d0_ext_list_page2.jpg)

<details>
<summary><b>Step-by-step GUI guide</b></summary>

#### Step 1 — Create External Threat Feed

Navigate to **Security Fabric > External Connectors > Create New > Threat Feeds > IP Address**

| Field | Value |
|-------|-------|
| **Name** | `ThreatIntel-IPFeed` |
| **URL** | `https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt` |
| **Refresh Rate** | `60` minutes |
| **Status** | Enabled |

After saving, the feed should show a green status with the number of entries loaded under **Security Fabric > External Connectors**.

#### Step 2 — Create Inbound Block Policy

Navigate to **Policy & Objects > Firewall Policy > Create New**

| Field | Value |
|-------|-------|
| **Name** | `Block-ThreatIntel` |
| **Incoming Interface** | `wan1` (or your WAN interface) |
| **Outgoing Interface** | `any` |
| **Source** | `ThreatIntel-IPFeed` |
| **Destination** | `all` |
| **Action** | **DENY** |
| **Log Violation Traffic** | Enabled |

> **Important:** Place this policy **above** your allow rules so it takes priority.

#### Step 3 (Optional) — Block Outbound to Threat IPs

Create a second policy to block **internal hosts communicating with known malicious IPs** (C2 callback detection):

| Field | Value |
|-------|-------|
| **Name** | `Block-Outbound-ThreatIntel` |
| **Incoming Interface** | `lan` / `internal` |
| **Outgoing Interface** | `wan1` |
| **Source** | `all` |
| **Destination** | `ThreatIntel-IPFeed` |
| **Action** | **DENY** |
| **Log Violation Traffic** | Enabled |

</details>

<details>
<summary><b>FortiGate CLI alternative</b></summary>

```
config system external-resource
    edit "ThreatIntel-IPFeed"
        set type address
        set resource "https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt"
        set refresh-rate 60
    next
end

config firewall policy
    edit 0
        set name "Block-ThreatIntel"
        set srcintf "wan1"
        set dstintf "any"
        set srcaddr "ThreatIntel-IPFeed"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set logtraffic all
    next
end
```

</details>

---

### Palo Alto

> Full documentation: [PAN-OS External Dynamic Lists](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/policy/use-an-external-dynamic-list-in-policy/external-dynamic-list)

![Palo Alto External Dynamic List](https://docs.paloaltonetworks.com/content/dam/techdocs/en_US/dita/_graphics/11-0/content-inspection/edl-predefined-lists.png)

<details>
<summary><b>Step-by-step GUI guide</b></summary>

#### Step 1 — Create External Dynamic List

Navigate to **Objects > External Dynamic Lists > Add**

| Field | Value |
|-------|-------|
| **Name** | `ThreatIntel-IPFeed` |
| **Type** | `IP List` |
| **Source** | `https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt` |
| **Repeat** | `Hourly` |

Click **OK** to save.

#### Step 2 — Create Inbound Block Policy

Navigate to **Policies > Security > Add**

| Field | Value |
|-------|-------|
| **Name** | `Block-ThreatIntel-Inbound` |
| **Source Zone** | `Untrust` |
| **Source Address** | `ThreatIntel-IPFeed` |
| **Destination Zone** | `any` |
| **Action** | **Drop** |
| **Log at Session End** | Enabled |
| **Log Forwarding** | Select your log profile |

> **Important:** Move this rule **above** your allow rules.

#### Step 3 — Block Outbound (C2 Detection)

Add a second rule:

| Field | Value |
|-------|-------|
| **Name** | `Block-ThreatIntel-Outbound` |
| **Source Zone** | `Trust` |
| **Source Address** | `any` |
| **Destination Zone** | `Untrust` |
| **Destination Address** | `ThreatIntel-IPFeed` |
| **Action** | **Drop** |
| **Log at Session End** | Enabled |

#### Step 4 — Commit

Click **Commit** to apply changes. Verify the EDL is loaded under **Objects > External Dynamic Lists** — click the entry to see the number of IPs loaded.

</details>

<details>
<summary><b>Palo Alto CLI alternative</b></summary>

```
set address ThreatIntel-IPFeed external-dynamic-list url "https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt"
set address ThreatIntel-IPFeed external-dynamic-list type ip
set address ThreatIntel-IPFeed external-dynamic-list repeat hourly
```

</details>

### iptables
```bash
curl -s https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt \
  | while read ip; do iptables -A INPUT -s "$ip" -j DROP; done
```

### nftables
```bash
curl -s https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt \
  | nft add element inet filter blocklist
```

### fail2ban
Use as a persistent banlist in `jail.local`:
```ini
[threat-intel]
banaction = iptables-allports
bantime = 3600
findtime = 3600
```

### Suricata / Snort
Generate rules from the feed:
```bash
curl -s https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt \
  | awk '{print "drop ip "$1" any -> any any (msg:\"ThreatIntel Block\"; sid:9000001; rev:1;)"}' \
  > /etc/suricata/rules/threat-intel.rules
```

### Splunk / QRadar / Wazuh / ELK
Import the raw URL as a **threat intelligence feed** (lookup table or CSV input).

### STIX/TAXII Integration
The aggregator produces a STIX 2.1 JSON bundle at `output/stix_bundle.json`. Import it into any STIX-compatible platform:
```python
import json
with open("output/stix_bundle.json") as f:
    bundle = json.load(f)
print(f"{len(bundle['objects']) - 1} indicators loaded")
# Each indicator includes: pattern, confidence score, source labels, category
```

### Python
```python
import requests
blocklist = requests.get(
    "https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt"
).text.strip().split("\n")
print(f"{len(blocklist)} IPs loaded")
```

### CSV Analysis
The CSV output at `output/blacklist.csv` includes per-IP metadata:
```python
import csv
with open("output/blacklist.csv") as f:
    reader = csv.DictReader(f)
    multi_source = [r for r in reader if int(r["source_count"]) > 2]
    print(f"{len(multi_source)} IPs flagged by 3+ sources")
```

---

## Sources (17 feeds)

| Source | Type | Region | Registration |
|--------|------|--------|-------------|
| Spamhaus DROP / DROPv6 | CIDR blocklist | Global | None |
| Blocklist.de (7 categories) | Attack IPs | Global | None |
| CINS Army | Threat list | Global | None |
| Emerging Threats | Compromised IPs | Global | None |
| BinaryDefense | Artillery ban | Global | None |
| GreenSnow | Threat list | Global | None |
| Tor Exit Nodes | Anonymizer | Global | None |
| Stamparm IPsum | Multi-source aggregation | Global | None |
| **SGB** | Gov. threat feed | Turkey | None |
| **RTBH** | National blocklist | Turkey | None |
| AbuseIPDB | Crowd-sourced reports | Global | Free API key |
| AlienVault OTX | Pulse indicators | Global | Free API key |

> **Turkey-specific sources (SGB, RTBH) are rarely found in global aggregators** - this project includes them natively.

---

## Output Files

| File | Format | Use Case |
|------|--------|----------|
| [`hourlyIPv4.txt`](output/hourlyIPv4.txt) | Raw IPs, one per line | Firewall / EDL import |
| [`ipv4_blacklist.txt`](output/ipv4_blacklist.txt) | IPs + metadata header | Analysis / audit |
| [`ipv6_blacklist.txt`](output/ipv6_blacklist.txt) | IPv6 addresses + CIDRs | IPv6-capable systems |
| [`blacklist_full.json`](output/blacklist_full.json) | Full JSON dataset | API / programmatic use |
| [`blacklist.csv`](output/blacklist.csv) | CSV with per-IP metadata | SIEM enrichment / analysis |
| [`stix_bundle.json`](output/stix_bundle.json) | STIX 2.1 JSON bundle | Threat intel platforms |
| [`health_report.md`](output/health_report.md) | Markdown report | Monitoring |

### CSV Format

```csv
ip,type,is_cidr,sources,source_count,category,first_seen,last_seen
1.2.3.4,ipv4,False,Blocklist.de (ssh)|Stamparm IPsum,2,brute-force,2026-04-14T12:00:00+00:00,2026-04-14T12:00:00+00:00
5.6.0.0/16,ipv4,True,Spamhaus DROP,1,infrastructure,2026-04-14T12:00:00+00:00,2026-04-14T12:00:00+00:00
```

| Column | Description |
|--------|------------|
| `ip` | IP address or CIDR range |
| `type` | `ipv4` or `ipv6` |
| `is_cidr` | `True` if CIDR range, `False` if individual IP |
| `sources` | Pipe-separated list of source names that reported this IP |
| `source_count` | Number of independent sources (higher = more confident) |
| `category` | Threat category derived from primary source |
| `first_seen` / `last_seen` | Timestamps of observation |

### STIX 2.1 Bundle

Each IP becomes a STIX `indicator` object with:
- **Pattern**: `[ipv4-addr:value = '1.2.3.4']` (STIX pattern syntax)
- **Confidence**: 0-100, scaled by number of reporting sources (20 per source, capped at 100)
- **Labels**: Threat category + source names
- **Identity**: Aggregator system as the producer

### Deduplication Report

The health report (`output/health_report.md`) now includes source overlap analysis:
- How many IPs are unique to a single source vs. found in multiple sources
- Per-source contribution: unique IPs vs. overlapping IPs
- Top source-pair overlaps (which sources share the most IPs)

---

## IP Whitelisting

Prevent false positives by adding trusted IPs to `whitelist.txt`:

```
# CDN ranges — never block
104.16.0.0/12       # Cloudflare
8.8.8.8             # Google DNS
1.1.1.0/24          # Cloudflare DNS

# Our infrastructure
203.0.113.10
```

**How it works:**
- One IP or CIDR per line, comments start with `#`
- Individual IPs are filtered by exact match or CIDR containment
- Any block CIDR overlapping a whitelisted address or range is omitted in full; this protects the whitelist without expanding ranges into many smaller blocks
- Supports both IPv4 and IPv6
- Whitelist stats appear in the health report and console summary
- The whitelist is applied **before** IPs enter the output files

---

## Reliability & Failsafe

This isn't a script that breaks silently. Every failure is tracked, reported, and isolated.

| Mechanism | What It Does |
|-----------|-------------|
| **Parallel Fetching** | Sources fetched using a bounded thread pool and thread-local `requests.Session` connections; default 10 workers |
| **Error Isolation** | Each source is fetched independently; failures use its last cached data when available |
| **Auto Retry** | Up to 3 attempts: 2s/4s for transient errors; 10s/30s plus 0–2s jitter for 429 without a cooldown. Honor server cooldowns up to 30s; defer longer cooldowns to cache without retrying early. Permanent 4xx errors skip retry |
| **Rollback Protection** | Refuse low-success collections; stage all feed formats before publishing, replace individual files atomically, and restore replaced files on a publishing error |
| **Health Tracking** | `source_health.json` records every run: consecutive failures, last success, IP counts |
| **Stale Detection** | Sources with no data for 30+ days are flagged |
| **GitHub Issue Alerts** | Update one existing source-health issue during an outage; auto-close health issues on recovery |
| **Exit Codes** | `0` = OK, `1` = partial source failure, `2` = fatal processing or publishing failure; Actions commits only for codes 0 and 1 |
| **IP Whitelisting** | Trusted IPs/CIDRs in `whitelist.txt` are never included in output |
| **Dedup Metrics** | Source overlap analysis helps identify redundant or low-value sources |

---

## Self-Hosting

```bash
git clone https://github.com/ziyadnz/threat-intel-ip-feeds.git
cd threat-intel-ip-feeds
pip install -r requirements-runtime.txt
python run.py
```

> **Requires Python 3.10+**. GitHub Actions runs Python 3.13.

### With API Keys (optional)
```bash
export ABUSEIPDB_API_KEY="your_key"    # https://www.abuseipdb.com/register
export OTX_API_KEY="your_key"          # https://otx.alienvault.com
python run.py
```

### Refresh, caching, and publishing

AbuseIPDB refreshes when its last successful cached fetch is at least four hours old.
Scheduled cache reuse does not advance the source's last successful fetch time.
API failures preserve their error status even when cached IPs are available; missing API
keys are reported as skipped. OTX keeps the last complete cache when some pages fail,
and reports any newly collected partial data separately from a complete successful fetch.
Existing SGB pagination delays, OTX concurrency limits, and HTTP timeouts remain in place.

`MAX_RETRY_AFTER` sets the longest server-requested cooldown to wait through (default
30 seconds, also explicit in the Actions workflow). A longer cooldown defers that host
for the rest of the process, immediately using source cache when available. Other hosts
continue normally. Already in-flight requests can finish, but OTX submits no later page
batches or outer retries after a deferral. Cooldowns are not shortened into early retries.
Without a server-provided cooldown, HTTP 429 uses 10s and 30s waits plus 0–2s jitter;
normal transient failures retain 2s/4s backoff. This limit does not shorten request timeouts
or the existing SGB pagination delay. A fresh process starts with no deferred hosts.

CSV `first_seen` persists from the previous published CSV; `last_seen` advances on fresh
successful observations, not cache reuse. An IP that disappears and later returns begins
a new observation period. Existing history before this feature cannot be reconstructed.
STIX ordering and bundle IDs are deterministic for unchanged content; indicator timestamps
change only with the relevant observation or content changes. Health records and fetch
cache timestamps still update to describe actual refreshes, so every run may still commit.

Actions serializes collection runs and has a 90-minute safety timeout. Fatal runs do not
commit output. Logs report fetching, processing, publishing, and total application time.
`CONNECTOR_LIMIT` controls the source worker count (default 10); it does not change OTX's
separate three-page concurrency limit. No Actions dependency cache or artifacts are added.

Files are published with atomic individual replacements and rollback on caught errors.
A process kill during the multi-file publish can still leave a mixture of old and new files;
a filesystem-wide transaction is not provided. Feed URLs and formats are preserved.

### Automate with cron
```bash
0 * * * * cd /path/to/threat-intel-ip-feeds && python run.py >> /var/log/threat-intel.log 2>&1
```

### Running Tests
```bash
pip install -r requirements.txt
python -m pytest tests/unit/ -v
```

The test suite covers:
- Domain entities, value objects, and services (pure logic, zero I/O)
- Use case orchestration with stub ports
- Requests retry logic, server-directed delays, and thread-local sessions
- Source parsing, API pagination, and four-hour cache refresh behavior with fake HTTP clients
- CSV, STIX, raw, JSON output format correctness
- Staged output publishing, rollback, cache freshness, and health tracking

---

## How It Works

```mermaid
flowchart TD
    A[Start - Every Hour] --> B[Load Whitelist + Health State]
    B --> C[Launch bounded source fetch threads]
    C --> D{HTTP Request}
    D -->|Success| E[Extract & Validate IPs]
    D -->|Fail| F{Retry < 3?}
    F -->|Yes| G[Bounded retry or cache fallback] --> D
    F -->|No| H[Record Failure]
    E --> I[Record Success]
    H --> WF[Apply Whitelist Filter]
    I --> WF
    WF --> J[Classify IPv4 / IPv6 + Track Source Attribution]
    J --> K{Success Rate >= 20%?}
    K -->|Yes| L[Write Output Files]
    K -->|No| M[Rollback: Keep Existing Files]
    L --> L1[hourlyIPv4.txt]
    L --> L2[blacklist.csv]
    L --> L3[stix_bundle.json]
    L --> L4[blacklist_full.json]
    L1 & L2 & L3 & L4 --> N[Health Report + Dedup Metrics]
    M --> N
    N --> O{Issues Detected?}
    O -->|Yes| P[Open GitHub Issue]
    O -->|No| Q[Auto-Close Resolved Issues]
```

## Architecture

```mermaid
graph LR
    subgraph Sources
        GS[Global Sources<br/>15 feeds]
        TS[Turkey Sources<br/>SGB, RTBH]
        AS[API Sources<br/>AbuseIPDB, OTX]
    end

    subgraph Core
        CO[CollectThreatIntelUseCase<br/>asyncio.gather Concurrency<br/>+ Source Attribution]
        UT[AiohttpClient<br/>Async HTTP + Retry]
        CF[AppConfig<br/>Env-based Settings]
        WL[WhitelistFilter<br/>Domain Service]
    end

    subgraph Output
        OW[output_writer.py<br/>Rollback Protected]
        IPv4[ipv4_blacklist.txt]
        IPv6[ipv6_blacklist.txt]
        JSON[blacklist_full.json]
        CSV[blacklist.csv<br/>Per-IP Metadata]
        STIX[stix_bundle.json<br/>STIX 2.1 Bundle]
    end

    subgraph Health
        HT[health_tracker.py<br/>Persistent State]
        HR[health_report.py<br/>Markdown Report<br/>+ Dedup Metrics]
        NO[notifier.py<br/>GitHub Issues]
    end

    subgraph Tests
        TS2[tests/unit/<br/>80 async tests<br/>Mocked aiohttp]
    end

    MAIN[main.py<br/>Orchestrator] --> CO
    CO --> GS & TS & AS
    GS & TS & AS --> UT
    UT --> CF
    CO --> WL
    CO --> OW
    OW --> IPv4 & IPv6 & JSON & CSV & STIX
    CO --> HT
    HT --> HR
    HR --> NO
```

---

## Contributing

Issues and pull requests are welcome. If you know a free, public threat intel feed that's missing, open an issue.

## License

MIT
