"""Yardımcı fonksiyonlar: IP doğrulama, HTTP istekleri (retry destekli), regex."""

import re
import time
import ipaddress
import logging
from typing import Set, Dict, Optional

import requests

from config import REQUEST_TIMEOUT, MAX_RETRIES, RETRY_BACKOFF

logger = logging.getLogger(__name__)

# Regex desenleri
IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
IPV6_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}:'
    r'|:(?::[0-9a-fA-F]{1,4}){1,7}'
    r'|::(?:[fF]{4}:)?(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
    r'\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
    r'\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
    r'\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
CIDR_V4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2}\b'
)
CIDR_V6_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F:]*?/\d{1,3}\b'
)


def is_valid_public_ip(ip_str: str) -> bool:
    """IP adresinin geçerli ve public olup olmadığını kontrol eder."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast)
    except ValueError:
        return False


def is_ipv6(ip_str: str) -> bool:
    """Verilen string'in IPv6 olup olmadığını kontrol eder."""
    try:
        return isinstance(ipaddress.ip_address(ip_str), ipaddress.IPv6Address)
    except ValueError:
        try:
            return isinstance(ipaddress.ip_network(ip_str, strict=False), ipaddress.IPv6Network)
        except ValueError:
            return ":" in ip_str


def safe_request(url: str, headers: Optional[Dict] = None, timeout: int = REQUEST_TIMEOUT,
                 method: str = "GET", json_data: Optional[Dict] = None,
                 retries: int = MAX_RETRIES) -> Optional[requests.Response]:
    """Güvenli HTTP isteği - otomatik retry ve exponential backoff ile."""
    last_error = None

    for attempt in range(retries):
        try:
            if method == "POST":
                resp = requests.post(url, headers=headers, json=json_data,
                                     timeout=timeout, verify=True)
            else:
                resp = requests.get(url, headers=headers, timeout=timeout, verify=True)
            resp.raise_for_status()
            return resp

        except requests.exceptions.RequestException as e:
            last_error = e
            # 4xx hataları (429 hariç) retry yapma - kalıcı hatalar
            if hasattr(e, 'response') and e.response is not None:
                status = e.response.status_code
                if 400 <= status < 500 and status != 429:
                    logger.error(f"[{url}] Kalıcı hata ({status}), retry yapılmıyor: {e}")
                    return None

            if attempt < retries - 1:
                wait = RETRY_BACKOFF ** (attempt + 1)
                logger.warning(f"[{url}] Deneme {attempt + 1}/{retries} başarısız, "
                               f"{wait}s sonra tekrar: {e}")
                time.sleep(wait)
            else:
                logger.error(f"[{url}] {retries} deneme sonrası başarısız: {e}")

    return None


def extract_ips_from_text(text: str) -> Set[str]:
    """Metin içinden geçerli public IPv4 adreslerini çıkarır."""
    return {ip for ip in IPV4_PATTERN.findall(text) if is_valid_public_ip(ip)}
