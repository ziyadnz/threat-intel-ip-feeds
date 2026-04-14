"""GitHub Issue notifier via gh CLI."""

from __future__ import annotations

import json
import logging
import os
import subprocess

from threat_intel.domain.ports import Notifier

logger = logging.getLogger(__name__)


class GitHubIssueNotifier(Notifier):
    """Creates/closes GitHub Issues using the gh CLI. Only active in CI."""

    LABEL = "source-health"

    def __init__(self, timeout: int = 30):
        self._timeout = timeout

    def notify(self, title: str, body: str) -> None:
        if not self._is_ci():
            logger.info("Not in CI, skipping GitHub notification.")
            return

        self._ensure_label()

        if self._has_open_issue(title):
            logger.info("Open issue already exists, skipping.")
            return

        result = self._gh([
            "issue", "create",
            "--title", title,
            "--body", body,
            "--label", self.LABEL,
        ])
        if result.returncode == 0:
            logger.info(f"GitHub Issue created: {result.stdout.strip()}")
        else:
            logger.error(f"GitHub Issue creation failed: {result.stderr}")

    def close_resolved(self) -> None:
        if not self._is_ci():
            return

        result = self._gh([
            "issue", "list",
            "--label", self.LABEL,
            "--state", "open",
            "--json", "number",
        ])
        if result.returncode != 0:
            return

        try:
            issues = json.loads(result.stdout)
        except json.JSONDecodeError:
            return

        for issue in issues:
            close_result = self._gh([
                "issue", "close", str(issue["number"]),
                "--comment", "All sources healthy, auto-closed.",
            ])
            if close_result.returncode == 0:
                logger.info(f"Issue #{issue['number']} closed.")

    @staticmethod
    def _is_ci() -> bool:
        return os.environ.get("GITHUB_ACTIONS") == "true"

    def _gh(self, args: list) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                ["gh"] + args,
                capture_output=True, text=True, timeout=self._timeout,
            )
        except FileNotFoundError:
            logger.warning("gh CLI not found.")
            return subprocess.CompletedProcess(args, 1, "", "gh not found")
        except Exception as e:
            logger.error(f"gh command failed: {e}")
            return subprocess.CompletedProcess(args, 1, "", str(e))

    def _ensure_label(self):
        self._gh([
            "label", "create", self.LABEL,
            "--description", "Automated source health alerts",
            "--color", "d93f0b", "--force",
        ])

    def _has_open_issue(self, title: str) -> bool:
        result = self._gh([
            "issue", "list",
            "--label", self.LABEL,
            "--state", "open",
            "--limit", "5",
            "--json", "title,number",
        ])
        return result.returncode == 0 and title in result.stdout
