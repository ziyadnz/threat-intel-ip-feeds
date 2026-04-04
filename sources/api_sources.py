"""API key gerektiren blacklist kaynakları: AbuseIPDB, AlienVault OTX."""

import json
import logging
from typing import Set, Tuple

import requests

from utils import is_valid_public_ip
from config import ABUSEIPDB_API_KEY, OTX_API_KEY, REQUEST_TIMEOUT

logger = logging.getLogger(__name__)


def fetch_abuseipdb() -> Tuple[Set[str], str]:
    """AbuseIPDB blacklist (API key gerekli)."""
    source = "AbuseIPDB"
    ips = set()
    if not ABUSEIPDB_API_KEY:
        logger.warning(f"[{source}] API key yok, atlanıyor.")
        return ips, source

    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"confidenceMinimum": 90, "limit": 10000}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers=headers, params=params, timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        for entry in resp.json().get("data", []):
            ip = entry.get("ipAddress", "")
            if is_valid_public_ip(ip):
                ips.add(ip)
    except requests.exceptions.RequestException as e:
        logger.error(f"[{source}] İstek hatası: {e}")
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"[{source}] JSON parse hatası: {e}")

    logger.info(f"[{source}] {len(ips)} IP")
    return ips, source


def fetch_alienvault_otx() -> Tuple[Set[str], str]:
    """AlienVault OTX pulse IP'leri (API key gerekli). Sayfalama ile tum pulse'lari tarar."""
    source = "AlienVault OTX"
    ips = set()
    if not OTX_API_KEY:
        logger.warning(f"[{source}] API key yok, atlanıyor.")
        return ips, source

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    page = 1
    max_pages = 20

    try:
        while page <= max_pages:
            url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&page={page}"
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])
            if not results:
                break
            for pulse in results:
                for indicator in pulse.get("indicators", []):
                    if indicator.get("type") in ("IPv4", "IPv6"):
                        ip = indicator.get("indicator", "")
                        if is_valid_public_ip(ip):
                            ips.add(ip)
            # Sonraki sayfa var mi
            if not data.get("next"):
                break
            page += 1
    except requests.exceptions.RequestException as e:
        logger.error(f"[{source}] İstek hatası (sayfa {page}): {e}")
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"[{source}] JSON parse hatası: {e}")

    logger.info(f"[{source}] {len(ips)} IP ({page} sayfa)")
    return ips, source
