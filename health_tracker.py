"""Kaynak sağlık durumu takibi - persistent JSON dosyası ile."""

import json
import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

from config import HEALTH_FILE, STALE_THRESHOLD_DAYS

logger = logging.getLogger(__name__)


def load_health(filepath: str = HEALTH_FILE) -> Dict:
    """Sağlık dosyasını yükler. Dosya yoksa veya bozuksa boş dict döner."""
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Sağlık dosyası okunamadı, sıfırdan başlanıyor: {e}")
        return {}


def save_health(health: Dict, filepath: str = HEALTH_FILE):
    """Sağlık dosyasını atomik olarak yazar (temp + rename)."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    tmp_path = filepath + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(health, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, filepath)
    except OSError as e:
        logger.error(f"Sağlık dosyası yazılamadı: {e}")


def _ensure_entry(health: Dict, source_name: str) -> Dict:
    """Kaynak için entry yoksa varsayılan oluşturur."""
    if source_name not in health:
        health[source_name] = {
            "last_success": None,
            "last_failure": None,
            "last_failure_reason": None,
            "last_ip_count": 0,
            "consecutive_failures": 0,
            "total_runs": 0,
            "total_failures": 0,
        }
    return health[source_name]


def record_success(health: Dict, source_name: str, ip_count: int):
    """Başarılı çalışmayı kaydeder."""
    entry = _ensure_entry(health, source_name)
    entry["last_success"] = datetime.now(timezone.utc).isoformat()
    entry["last_ip_count"] = ip_count
    entry["consecutive_failures"] = 0
    entry["total_runs"] += 1


def record_failure(health: Dict, source_name: str, error_msg: str):
    """Başarısız çalışmayı kaydeder."""
    entry = _ensure_entry(health, source_name)
    entry["last_failure"] = datetime.now(timezone.utc).isoformat()
    entry["last_failure_reason"] = str(error_msg)[:500]
    entry["consecutive_failures"] += 1
    entry["total_runs"] += 1
    entry["total_failures"] += 1


def record_no_data(health: Dict, source_name: str):
    """Kaynak çalıştı ama 0 IP döndü - potansiyel sorun."""
    entry = _ensure_entry(health, source_name)
    entry["total_runs"] += 1
    # last_success güncellenmez - veri gelmediği için stale tespiti çalışsın


def get_stale_sources(health: Dict) -> List[Dict]:
    """30+ gündür veri gelmemiş kaynakları döner."""
    stale = []
    threshold = datetime.now(timezone.utc) - timedelta(days=STALE_THRESHOLD_DAYS)

    for name, entry in health.items():
        last_success = entry.get("last_success")
        if last_success is None:
            # Hiç başarılı olmamış - en az 1 run yapılmışsa stale say
            if entry.get("total_runs", 0) > 0:
                stale.append({
                    "source": name,
                    "last_success": "Hiç",
                    "days_since": "N/A",
                    "consecutive_failures": entry.get("consecutive_failures", 0),
                })
        else:
            try:
                last_dt = datetime.fromisoformat(last_success)
                if last_dt < threshold:
                    days = (datetime.now(timezone.utc) - last_dt).days
                    stale.append({
                        "source": name,
                        "last_success": last_success[:10],
                        "days_since": days,
                        "consecutive_failures": entry.get("consecutive_failures", 0),
                    })
            except (ValueError, TypeError):
                pass
    return stale


def get_failing_sources(health: Dict) -> List[Dict]:
    """Ardışık hatası olan kaynakları döner."""
    failing = []
    for name, entry in health.items():
        if entry.get("consecutive_failures", 0) > 0:
            failing.append({
                "source": name,
                "consecutive_failures": entry["consecutive_failures"],
                "last_failure": entry.get("last_failure", "?")[:10],
                "reason": entry.get("last_failure_reason", "Bilinmiyor"),
            })
    return sorted(failing, key=lambda x: -x["consecutive_failures"])
