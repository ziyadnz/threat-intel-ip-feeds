# Threat Intel IP Feeds

![Updated](https://img.shields.io/github/last-commit/ziyadnz/threat-intel-ip-feeds/main?label=last%20update)
![Build Status](https://img.shields.io/github/actions/workflow/status/ziyadnz/threat-intel-ip-feeds/update.yml?label=hourly%20run)
![License](https://img.shields.io/github/license/ziyadnz/threat-intel-ip-feeds)
![Stars](https://img.shields.io/github/stars/ziyadnz/threat-intel-ip-feeds?style=social)

**Hourly updated, firewall-ready IP blocklist aggregated from 19+ threat intelligence sources. ~120,000+ unique malicious IPs, deduplicated, validated, and ready to import.**

```
https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt
```
Copy the URL above into your firewall, SIEM, or any tool that accepts a plain-text IP blocklist. One IP/CIDR per line, no comments, no headers. Updated every hour.

---

## Quick Usage Examples

### pfSense / OPNsense
**Firewall > Aliases > URLs** — paste the raw URL, set update frequency to 1 hour.

### FortiGate (GUI)

<details>
<summary><b>Click to expand step-by-step guide with screenshots</b></summary>

#### Step 1 — Create External Threat Feed

Navigate to **Security Fabric > External Connectors > Create New**

Select **Threat Feeds > IP Address**

![Step 1 - External Connectors](docs/images/fortigate-step1-external-connectors.png)

#### Step 2 — Configure the Feed

| Field | Value |
|-------|-------|
| **Name** | `ThreatIntel-IPFeed` |
| **URL** | `https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt` |
| **Refresh Rate** | `60` minutes |
| **Status** | Enabled |

![Step 2 - Feed Configuration](docs/images/fortigate-step2-feed-config.png)

#### Step 3 — Verify the Feed is Active

After saving, go back to **Security Fabric > External Connectors**. The feed should show a green status with the number of entries loaded.

![Step 3 - Feed Status](docs/images/fortigate-step3-feed-status.png)

#### Step 4 — Create Firewall Policy

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

![Step 4 - Firewall Policy](docs/images/fortigate-step4-firewall-policy.png)

#### Step 5 (Optional) — Block Outbound to Threat IPs

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

#### FortiGate CLI Alternative
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

---

### Palo Alto (GUI)

<details>
<summary><b>Click to expand step-by-step guide with screenshots</b></summary>

#### Step 1 — Create External Dynamic List

Navigate to **Objects > External Dynamic Lists > Add**

| Field | Value |
|-------|-------|
| **Name** | `ThreatIntel-IPFeed` |
| **Type** | `IP List` |
| **Source** | `https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt` |
| **Repeat** | `Hourly` |

![Step 1 - External Dynamic List](docs/images/paloalto-step1-edl.png)

Click **OK** to save.

#### Step 2 — Create Security Policy

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

![Step 2 - Security Policy](docs/images/paloalto-step2-security-policy.png)

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

Click **Commit** to apply changes. Verify the EDL is loaded under **Objects > External Dynamic Lists** — click **more** on the entry to see the number of IPs loaded.

![Step 4 - Verify EDL](docs/images/paloalto-step3-verify.png)

</details>

#### Palo Alto CLI Alternative
```
set address ThreatIntel-IPFeed external-dynamic-list url "https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt"
set address ThreatIntel-IPFeed external-dynamic-list type ip
set address ThreatIntel-IPFeed external-dynamic-list repeat hourly
```

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

### Python
```python
import requests
blocklist = requests.get(
    "https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt"
).text.strip().split("\n")
print(f"{len(blocklist)} IPs loaded")
```

---

## Sources (19 feeds)

| Source | Type | Region | Registration |
|--------|------|--------|-------------|
| Spamhaus DROP / DROPv6 | CIDR blocklist | Global | None |
| Feodo Tracker (abuse.ch) | Botnet C2 | Global | None |
| DShield / SANS ISC | Intel feed | Global | None |
| Blocklist.de (7 categories) | Attack IPs | Global | None |
| CINS Army | Threat list | Global | None |
| Emerging Threats | Compromised IPs | Global | None |
| BinaryDefense | Artillery ban | Global | None |
| GreenSnow | Threat list | Global | None |
| Tor Exit Nodes | Anonymizer | Global | None |
| Stamparm IPsum | Multi-source aggregation | Global | None |
| **USOM** | Gov. threat feed | Turkey | None |
| **RTBH** | National blocklist | Turkey | None |
| AbuseIPDB | Crowd-sourced reports | Global | Free API key |
| AlienVault OTX | Pulse indicators | Global | Free API key |

> **Turkey-specific sources (USOM, RTBH) are rarely found in global aggregators** - this project includes them natively.

---

## Output Files

| File | Format | Use Case |
|------|--------|----------|
| [`hourlyIPv4.txt`](output/hourlyIPv4.txt) | Raw IPs, one per line | Firewall / EDL import |
| [`ipv4_blacklist.txt`](output/ipv4_blacklist.txt) | IPs + metadata header | Analysis / audit |
| [`ipv6_blacklist.txt`](output/ipv6_blacklist.txt) | IPv6 addresses + CIDRs | IPv6-capable systems |
| [`blacklist_full.json`](output/blacklist_full.json) | Full JSON dataset | API / programmatic use |
| [`health_report.md`](output/health_report.md) | Markdown report | Monitoring |

---

## Reliability & Failsafe

This isn't a script that breaks silently. Every failure is tracked, reported, and isolated.

| Mechanism | What It Does |
|-----------|-------------|
| **Error Isolation** | Each source runs independently. One failure never affects the other 18+ |
| **Auto Retry** | Failed requests retry 3x with exponential backoff (2s, 4s, 8s). Permanent 4xx errors skip retry |
| **Rollback Protection** | If success rate drops below 20%, existing output files are preserved — not overwritten with bad data |
| **Health Tracking** | `source_health.json` records every run: consecutive failures, last success, IP counts |
| **Stale Detection** | Sources with no data for 30+ days are flagged |
| **GitHub Issue Alerts** | Auto-creates issues on failure, auto-closes on recovery |
| **Exit Codes** | `0` = OK, `1` = partial failure (output written), `2` = critical (output preserved) |

---

## Self-Hosting

```bash
git clone https://github.com/ziyadnz/threat-intel-ip-feeds.git
cd threat-intel-ip-feeds
pip install -r requirements.txt
python main.py
```

### With API Keys (optional)
```bash
export ABUSEIPDB_API_KEY="your_key"    # https://www.abuseipdb.com/register
export OTX_API_KEY="your_key"          # https://otx.alienvault.com
python main.py
```

### Automate with cron
```bash
0 * * * * cd /path/to/threat-intel-ip-feeds && python main.py >> /var/log/threat-intel.log 2>&1
```

---

## How It Works

```mermaid
flowchart TD
    A[Start - Every Hour] --> B[Load 19+ Sources in Parallel]
    B --> C{HTTP Request}
    C -->|Success| D[Extract & Validate IPs]
    C -->|Fail| E{Retry < 3?}
    E -->|Yes| F[Backoff 2s/4s/8s] --> C
    E -->|No| G[Record Failure]
    D --> H[Record Success]
    G --> J[Classify IPv4 / IPv6]
    H --> J
    J --> K{Success Rate >= 20%?}
    K -->|Yes| L[Write Output Files]
    K -->|No| M[Rollback: Keep Existing Files]
    L --> N[Health Report]
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
        TS[Turkey Sources<br/>USOM, RTBH]
        AS[API Sources<br/>AbuseIPDB, OTX]
    end

    subgraph Core
        CO[collector.py<br/>Parallel Engine]
        UT[utils.py<br/>HTTP + Retry]
        CF[config.py<br/>Settings]
    end

    subgraph Output
        OW[output_writer.py<br/>Rollback Protected]
        IPv4[ipv4_blacklist.txt]
        IPv6[ipv6_blacklist.txt]
        JSON[blacklist_full.json]
    end

    subgraph Health
        HT[health_tracker.py<br/>Persistent State]
        HR[health_report.py<br/>Markdown Report]
        NO[notifier.py<br/>GitHub Issues]
    end

    MAIN[main.py<br/>Orchestrator] --> CO
    CO --> GS & TS & AS
    GS & TS & AS --> UT
    UT --> CF
    CO --> OW
    OW --> IPv4 & IPv6 & JSON
    CO --> HT
    HT --> HR
    HR --> NO
```

---

## Contributing

Issues and pull requests are welcome. If you know a free, public threat intel feed that's missing, open an issue.

## License

MIT
