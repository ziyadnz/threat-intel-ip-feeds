"""Türkiye bazlı blacklist kaynakları: USOM, RTBH."""

import time
import logging
from typing import Set, Tuple

from utils import safe_request, extract_ips_from_text, is_valid_public_ip

logger = logging.getLogger(__name__)


def fetch_usom() -> Tuple[Set[str], str]:
    """USOM (Türkiye) zararlı IP adresleri."""
    source = "USOM (Türkiye)"
    ips = set()
    page = 1
    max_ips = 10000
    headers = {"accept": "application/json"}

    while len(ips) < max_ips:
        url = f"https://www.usom.gov.tr/api/address/index?type=ip&page={page}"
        resp = safe_request(url, headers=headers)
        data = resp.json()
        models = data.get("models", [])
        if not models:
            break
        for entry in models:
            addr = entry.get("url", "")
            if addr:
                clean_ip = addr.strip()
                if is_valid_public_ip(clean_ip):
                    ips.add(clean_ip)
                    if len(ips) >= max_ips:
                        break
        total_count = data.get("totalCount", 0)
        page_size = data.get("pageSize", 100)
        if page * page_size >= total_count:
            break
        page += 1
        time.sleep(0.5)  # Rate limit korumasi

    logger.info(f"[{source}] {len(ips)} IP ({page} sayfa)")
    return ips, source


def fetch_rtbh() -> Tuple[Set[str], str]:
    """RTBH (Türkiye) listesi."""
    source = "RTBH (Türkiye)"
    resp = safe_request("https://list.rtbh.com.tr/output.txt")
    ips = extract_ips_from_text(resp.text)
    logger.info(f"[{source}] {len(ips)} IP")
    return ips, source
