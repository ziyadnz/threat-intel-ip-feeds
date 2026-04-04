"""Yapılandırma ayarları."""

import os

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# API Keys (GitHub Secrets veya ortam değişkeni olarak tanımlanmalı)
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

# Çıktı dosyaları
OUTPUT_DIR = os.path.join(_BASE_DIR, "output")
IPV4_FILE = os.path.join(OUTPUT_DIR, "ipv4_blacklist.txt")
IPV6_FILE = os.path.join(OUTPUT_DIR, "ipv6_blacklist.txt")
OUTPUT_JSON = os.path.join(OUTPUT_DIR, "blacklist_full.json")
HEALTH_FILE = os.path.join(OUTPUT_DIR, "source_health.json")
HEALTH_REPORT = os.path.join(OUTPUT_DIR, "health_report.md")
LOG_FILE = os.path.join(_BASE_DIR, "aggregator.log")

# HTTP ayarları
REQUEST_TIMEOUT = 60
MAX_WORKERS = 10

# Retry ayarları
MAX_RETRIES = 3
RETRY_BACKOFF = 2  # saniye (exponential: 2, 4, 8)

# IPsum minimum skor
IPSUM_MIN_SCORE = 2

# Sağlık kontrol ayarları
STALE_THRESHOLD_DAYS = 30  # Bu kadar gün veri gelmezse uyar
MIN_SUCCESS_RATIO = 0.2    # Kaynakların en az %20'si başarılı olmalı, yoksa dosya üzerine yazma
