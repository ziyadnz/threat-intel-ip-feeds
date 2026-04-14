"""Source feed URLs — single source of truth for all endpoint addresses.

Changing a URL, adding a mirror, or switching to a proxy requires
editing only this file. No source adapter code needs to change.
"""

# Spamhaus
SPAMHAUS_DROP = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_DROPV6 = "https://www.spamhaus.org/drop/dropv6.txt"

# abuse.ch
FEODO_TRACKER = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"

# SANS / DShield
DSHIELD_INTELFEED = "https://isc.sans.edu/api/intelfeed?json"

# Blocklist.de — {service} is substituted at runtime
BLOCKLIST_DE = "https://lists.blocklist.de/lists/{service}.txt"

# CINS
CINS_ARMY = "https://cinsscore.com/list/ci-badguys.txt"

# Emerging Threats
EMERGING_THREATS = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

# BinaryDefense
BINARY_DEFENSE = "https://www.binarydefense.com/banlist.txt"

# GreenSnow
GREENSNOW = "https://blocklist.greensnow.co/greensnow.txt"

# Tor
TOR_EXIT_NODES = "https://check.torproject.org/torbulkexitlist"

# Stamparm IPsum
STAMPARM_IPSUM = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"

# Turkey
USOM_API = "https://www.usom.gov.tr/api/address/index"
RTBH = "https://list.rtbh.com.tr/output.txt"

# API sources
ABUSEIPDB_BLACKLIST = "https://api.abuseipdb.com/api/v2/blacklist"
ALIENVAULT_OTX_PULSES = "https://otx.alienvault.com/api/v1/pulses/subscribed"
