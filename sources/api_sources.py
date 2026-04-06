"""API key gerektiren blacklist kaynakları: AbuseIPDB, AlienVault OTX."""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Set, Tuple

import requests

from utils import is_valid_public_ip
from config import ABUSEIPDB_API_KEY, OTX_API_KEY, REQUEST_TIMEOUT, OUTPUT_DIR

# AbuseIPDB free plan: günde 5 blacklist isteği.
# Sadece bu saatlerde çalışır (UTC), geri kalan saatlerde atlanır.
ABUSEIPDB_ALLOWED_HOURS = {0, 5, 10, 15, 20}
ABUSEIPDB_CACHE_FILE = os.path.join(OUTPUT_DIR, "abuseipdb_cache.json")

logger = logging.getLogger(__name__)


def _save_abuseipdb_cache(ips: Set[str]):
    """Başarılı AbuseIPDB sonuçlarını cache'e yaz."""
    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ips": sorted(ips),
    }
    with open(ABUSEIPDB_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)


def _load_abuseipdb_cache() -> Set[str]:
    """Cache'ten son başarılı AbuseIPDB IP'lerini oku."""
    try:
        with open(ABUSEIPDB_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        ips = set(data.get("ips", []))
        ts = data.get("timestamp", "?")
        logger.info(f"[AbuseIPDB] Cache'ten yüklendi: {len(ips)} IP (son güncelleme: {ts})")
        return ips
    except (FileNotFoundError, json.JSONDecodeError):
        logger.warning("[AbuseIPDB] Cache bulunamadı veya okunamadı.")
        return set()


def fetch_abuseipdb() -> Tuple[Set[str], str]:
    """AbuseIPDB blacklist (API key gerekli, günde 5 istek limiti)."""
    source = "AbuseIPDB"
    ips = set()
    if not ABUSEIPDB_API_KEY:
        logger.warning(f"[{source}] API key yok, atlanıyor.")
        return ips, source

    current_hour = datetime.now(timezone.utc).hour
    if current_hour not in ABUSEIPDB_ALLOWED_HOURS:
        ips = _load_abuseipdb_cache()
        logger.info(f"[{source}] Saat {current_hour} UTC, izinli değil. Cache'ten {len(ips)} IP kullanılıyor.")
        return ips, source

    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"confidenceMinimum": 90, "limit": 10000}
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/blacklist",
        headers=headers, params=params, timeout=REQUEST_TIMEOUT
    )
    resp.raise_for_status()
    for entry in resp.json().get("data", []):
        ip = entry.get("ipAddress", "")
        if is_valid_public_ip(ip):
            ips.add(ip)

    if ips:
        _save_abuseipdb_cache(ips)
        logger.info(f"[{source}] {len(ips)} IP (cache güncellendi)")
    else:
        # API çağrısı yapıldı ama sonuç boş — cache'ten devam et
        ips = _load_abuseipdb_cache()
        logger.warning(f"[{source}] API'den 0 IP döndü, cache'ten {len(ips)} IP kullanılıyor.")

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

    logger.info(f"[{source}] {len(ips)} IP ({page} sayfa)")
    return ips, source
