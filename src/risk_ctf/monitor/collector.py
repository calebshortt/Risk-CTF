"""Cross-platform log collectors for MVP events."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import re
from pathlib import Path
from typing import Iterable

from risk_ctf.common.schema import now_utc_iso

LOGIN_RE = re.compile(r"Accepted .* for (?P<user>[A-Za-z0-9_.-]+) from (?P<ip>[0-9a-fA-F:.]+)")
SUDO_RE = re.compile(r"sudo: +(?P<user>[A-Za-z0-9_.-]+) :")
SSH_OUT_RE = re.compile(r"\bssh\s+(?P<target>[A-Za-z0-9_.-]+)")
WIN_LOGIN_RE = re.compile(
    r"An account was successfully logged on.*?Account Name:\s*(?P<user>[A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)
WIN_RUNAS_RE = re.compile(
    r"The process has been created.*?Account Name:\s*(?P<user>[A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)


@dataclass
class CollectorConfig:
    auth_log_path: str = ""
    secure_log_path: str = ""
    shell_history_paths: tuple[str, ...] = ()
    source_host: str = "unknown-host"
    source_country: str = "Unknown"


class MonitorCollector:
    def __init__(self, config: CollectorConfig) -> None:
        self._cfg = config
        self._seen_line_hashes: set[str] = set()

    def _read_existing_lines(self, path: str) -> Iterable[str]:
        p = Path(path)
        if not p.exists() or not p.is_file():
            return []
        try:
            return p.read_text(encoding="utf-8", errors="ignore").splitlines()[-300:]
        except OSError:
            return []

    def collect_events(self, monitor_id: str) -> list[dict]:
        events: list[dict] = []
        for line in self._read_existing_lines(self._cfg.auth_log_path):
            event = self._parse_auth_line(line, monitor_id)
            if event:
                events.append(event)
        for line in self._read_existing_lines(self._cfg.secure_log_path):
            event = self._parse_auth_line(line, monitor_id)
            if event:
                events.append(event)
        for hist_path in self._cfg.shell_history_paths:
            for line in self._read_existing_lines(hist_path):
                event = self._parse_shell_line(line, monitor_id)
                if event:
                    events.append(event)
        return events

    def _line_fingerprint(self, line: str) -> str:
        return hashlib.sha256(line.encode("utf-8")).hexdigest()

    def _new_line(self, line: str) -> bool:
        fp = self._line_fingerprint(line)
        if fp in self._seen_line_hashes:
            return False
        self._seen_line_hashes.add(fp)
        if len(self._seen_line_hashes) > 5000:
            self._seen_line_hashes = set(list(self._seen_line_hashes)[-2000:])
        return True

    def _base_event(self, monitor_id: str, user: str, event_type: str, payload: dict) -> dict:
        raw = f"{monitor_id}:{user}:{event_type}:{payload}:{now_utc_iso()}"
        event_id = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
        return {
            "event_type": event_type,
            "event_id": event_id,
            "ts": now_utc_iso(),
            "monitor_id": monitor_id,
            "actor_user": user,
            "source_host": self._cfg.source_host,
            "source_country": self._cfg.source_country,
            "payload": payload,
        }

    def _parse_auth_line(self, line: str, monitor_id: str) -> dict | None:
        if not self._new_line(line):
            return None
        login = LOGIN_RE.search(line)
        if login:
            user = login.group("user")
            return self._base_event(
                monitor_id=monitor_id,
                user=user,
                event_type="user_login",
                payload={"source_ip": login.group("ip")},
            )
        sudo = SUDO_RE.search(line)
        if sudo:
            user = sudo.group("user")
            return self._base_event(
                monitor_id=monitor_id,
                user=user,
                event_type="sudo_elevation",
                payload={"method": "sudo"},
            )
        ssh = SSH_OUT_RE.search(line)
        if ssh:
            user = "unknown"
            return self._base_event(
                monitor_id=monitor_id,
                user=user,
                event_type="remote_login",
                payload={
                    "destination_host": ssh.group("target"),
                    "destination_country": "Unknown",
                    "protocol": "ssh",
                },
            )
        win_login = WIN_LOGIN_RE.search(line)
        if win_login:
            user = win_login.group("user")
            return self._base_event(
                monitor_id=monitor_id,
                user=user,
                event_type="user_login",
                payload={"source_ip": "Unknown"},
            )
        win_runas = WIN_RUNAS_RE.search(line)
        if win_runas:
            user = win_runas.group("user")
            return self._base_event(
                monitor_id=monitor_id,
                user=user,
                event_type="sudo_elevation",
                payload={"method": "runas"},
            )
        return None

    def _parse_shell_line(self, line: str, monitor_id: str) -> dict | None:
        if not self._new_line(line):
            return None
        ssh = SSH_OUT_RE.search(line)
        if not ssh:
            return None
        return self._base_event(
            monitor_id=monitor_id,
            user="unknown",
            event_type="remote_login",
            payload={
                "destination_host": ssh.group("target"),
                "destination_country": "Unknown",
                "protocol": "ssh",
            },
        )


def default_collector_paths() -> tuple[str, str, tuple[str, ...]]:
    if os.name == "nt":
        # Optional files exported from Windows Event Viewer / agent pipeline.
        auth = r"C:\ProgramData\RiskCTF\security.log"
        secure = r"C:\ProgramData\ssh\logs\sshd.log"
        shell_hist = (
            r"C:\Users\Public\Documents\WindowsPowerShell\PSReadLine\ConsoleHost_history.txt",
        )
        return auth, secure, shell_hist
    return (
        "/var/log/auth.log",
        "/var/log/secure",
        ("/home/user/.bash_history", "/root/.bash_history"),
    )

