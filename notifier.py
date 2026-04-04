"""GitHub Issue bildirimi - gh CLI uzerinden."""

import os
import subprocess
import logging

logger = logging.getLogger(__name__)

LABEL = "source-health"


def _is_ci() -> bool:
    """GitHub Actions ortaminda mi?"""
    return os.environ.get("GITHUB_ACTIONS") == "true"


def _run_gh(args: list) -> subprocess.CompletedProcess:
    """gh CLI komutunu calistirir."""
    return subprocess.run(
        ["gh"] + args,
        capture_output=True, text=True, timeout=30
    )


def _ensure_label():
    """source-health label'i yoksa olusturur."""
    try:
        result = _run_gh(["label", "create", LABEL,
                          "--description", "Automated source health alerts",
                          "--color", "d93f0b",
                          "--force"])
        if result.returncode != 0 and "already exists" not in result.stderr:
            logger.warning(f"Label olusturulamadi: {result.stderr}")
    except Exception as e:
        logger.warning(f"Label kontrolu basarisiz: {e}")


def notify_github(title: str, body: str):
    """GitHub Issue olusturur. Sadece CI ortaminda calisir."""
    if not _is_ci():
        logger.info("CI ortami degil, GitHub bildirimi atlanıyor.")
        return

    _ensure_label()

    # Ayni baslikta acik issue var mi kontrol et
    try:
        search = _run_gh([
            "issue", "list",
            "--label", LABEL,
            "--state", "open",
            "--limit", "5",
            "--json", "title,number"
        ])
        if search.returncode == 0 and title in search.stdout:
            logger.info("Ayni baslikta acik issue zaten var, yeni issue acilmiyor.")
            return
    except Exception:
        pass

    try:
        result = _run_gh([
            "issue", "create",
            "--title", title,
            "--body", body,
            "--label", LABEL,
        ])
        if result.returncode == 0:
            logger.info(f"GitHub Issue olusturuldu: {result.stdout.strip()}")
        else:
            logger.error(f"GitHub Issue olusturulamadi: {result.stderr}")
    except FileNotFoundError:
        logger.warning("gh CLI bulunamadi, bildirim gonderilemedi.")
    except Exception as e:
        logger.error(f"GitHub bildirim hatasi: {e}")


def close_resolved_issues():
    """Tum kaynaklar saglikliysa acik issue'lari kapatir."""
    if not _is_ci():
        return

    try:
        result = _run_gh([
            "issue", "list",
            "--label", LABEL,
            "--state", "open",
            "--json", "number",
        ])
        if result.returncode != 0:
            return

        import json
        issues = json.loads(result.stdout)
        for issue in issues:
            close_result = _run_gh([
                "issue", "close", str(issue["number"]),
                "--comment", "Tum kaynaklar saglikli, otomatik kapatildi.",
            ])
            if close_result.returncode == 0:
                logger.info(f"Issue #{issue['number']} kapatildi.")
    except Exception as e:
        logger.warning(f"Issue kapatma hatasi: {e}")
