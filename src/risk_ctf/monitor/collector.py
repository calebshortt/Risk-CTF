"""Cross-platform log collectors for Phase 1–2 Risk-CTF events."""

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
# Session / reboot heuristics (auth.log, journal exports, Event Viewer dumps)
SESSION_CLOSED_RE = re.compile(
    r"session closed for user (?P<u>[A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)
LOGOUT_SESSION_RE = re.compile(
    r"(removed session|session \d+ logged out).*?user (?P<u>[A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)
HOST_REBOOT_RE = re.compile(
    r"(system is (?:rebooting|powering down)|"
    r"reboot|shutdown now|powering off|"
    r"will reboot|initiated restart)",
    re.IGNORECASE,
)
WIN_REBOOT_RE = re.compile(
    r"(restart is scheduled|windows will shut down|system is restarting)",
    re.IGNORECASE,
)
WGET_RE = re.compile(r"\bwget\s+(?P<rest>\S.{0,1800})", re.IGNORECASE)
CURL_RE = re.compile(
    r"\bcurl\s+(?P<rest>\S.{0,1800})",
    re.IGNORECASE,
)
IWR_RE = re.compile(
    r"\b(?:Invoke-WebRequest|iwr)\s+(?P<rest>.{1,2000})",
    re.IGNORECASE,
)
BITS_RE = re.compile(r"\bbitsadmin\b.{0,200}", re.IGNORECASE)
# Match /etc/passwd but not /etc/passwd-, /etc/passwd.bak, etc.
ETC_PASSWD_RE = re.compile(r"/etc/passwd(?![A-Za-z0-9_.-])")


@dataclass
class CollectorConfig:
    auth_log_path: str = ""
    secure_log_path: str = ""
    shell_history_paths: tuple[str, ...] = ()
    integrity_paths: tuple[str, ...] = ()
    source_host: str = "unknown-host"
    source_country: str = "Unknown"


class MonitorCollector:
    def __init__(self, config: CollectorConfig) -> None:
        self._cfg = config
        self._seen_line_hashes: set[str] = set()
        self._integrity_baseline: dict[str, tuple[int, int]] = {}
        self._tamper_emitted: set[str] = set()
        for raw in self._cfg.integrity_paths:
            p = Path(raw)
            if p.is_file():
                try:
                    st = p.stat()
                    self._integrity_baseline[str(p.resolve())] = (int(st.st_mtime_ns), int(st.st_size))
                except OSError:
                    continue

    def _read_existing_lines(self, path: str) -> Iterable[str]:
        p = Path(path)
        if not p.exists() or not p.is_file():
            return []
        try:
            return p.read_text(encoding="utf-8", errors="ignore").splitlines()[-400:]
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
                events.extend(self._parse_shell_line(line, monitor_id))
        events.extend(self._integrity_events(monitor_id))
        return events

    def _line_fingerprint(self, line: str) -> str:
        return hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()

    def _new_line(self, line: str) -> bool:
        fp = self._line_fingerprint(line)
        if fp in self._seen_line_hashes:
            return False
        self._seen_line_hashes.add(fp)
        if len(self._seen_line_hashes) > 8000:
            self._seen_line_hashes = set(list(self._seen_line_hashes)[-3500:])
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
        if ETC_PASSWD_RE.search(line):
            cmd = line.strip()[:512]
            return self._base_event(
                monitor_id=monitor_id,
                user="unknown",
                event_type="sensitive_file_access",
                payload={"path": "/etc/passwd", "command_line": cmd},
            )
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
        sc = SESSION_CLOSED_RE.search(line)
        if sc:
            target = sc.group("u")
            return self._base_event(
                monitor_id=monitor_id,
                user="unknown",
                event_type="session_terminate",
                payload={"target_user": target, "method": "session_closed"},
            )
        lo = LOGOUT_SESSION_RE.search(line)
        if lo:
            target = lo.group("u")
            return self._base_event(
                monitor_id=monitor_id,
                user=target,
                event_type="session_terminate",
                payload={"target_user": target, "method": "logout"},
            )
        if HOST_REBOOT_RE.search(line) or WIN_REBOOT_RE.search(line):
            return self._base_event(
                monitor_id=monitor_id,
                user="system",
                event_type="host_reboot",
                payload={"detail": line.strip()[:500]},
            )
        return None

    def _try_tool_download(self, stripped: str, monitor_id: str) -> dict | None:
        m = WGET_RE.search(stripped)
        if m:
            return self._base_event(
                monitor_id,
                "unknown",
                "tool_download",
                {"channel": "wget", "target": m.group("rest").strip()[:2048]},
            )
        m = CURL_RE.search(stripped)
        if m:
            return self._base_event(
                monitor_id,
                "unknown",
                "tool_download",
                {"channel": "curl", "target": m.group("rest").strip()[:2048]},
            )
        m = IWR_RE.search(stripped)
        if m:
            return self._base_event(
                monitor_id,
                "unknown",
                "tool_download",
                {"channel": "powershell", "target": m.group("rest").strip()[:2048]},
            )
        if BITS_RE.search(stripped):
            return self._base_event(
                monitor_id,
                "unknown",
                "tool_download",
                {"channel": "bitsadmin", "target": stripped[:2048]},
            )
        return None

    def _parse_shell_line(self, line: str, monitor_id: str) -> list[dict]:
        if not self._new_line(line):
            return []
        stripped = line.strip()
        if not stripped:
            return []
        if ETC_PASSWD_RE.search(stripped):
            cmd = stripped[:512]
            return [
                self._base_event(
                    monitor_id=monitor_id,
                    user="unknown",
                    event_type="sensitive_file_access",
                    payload={"path": "/etc/passwd", "command_line": cmd},
                )
            ]
        dl = self._try_tool_download(stripped, monitor_id)
        if dl:
            return [dl]
        ssh = SSH_OUT_RE.search(stripped)
        if ssh:
            return [
                self._base_event(
                    monitor_id=monitor_id,
                    user="unknown",
                    event_type="remote_login",
                    payload={
                        "destination_host": ssh.group("target"),
                        "destination_country": "Unknown",
                        "protocol": "ssh",
                    },
                )
            ]
        cmd = stripped[:512]
        if not cmd.strip():
            return []
        return [
            self._base_event(
                monitor_id=monitor_id,
                user="unknown",
                event_type="command_executed",
                payload={"command_line": cmd},
            )
        ]

    def _integrity_events(self, monitor_id: str) -> list[dict]:
        out: list[dict] = []
        for path_str, (base_mt, base_sz) in list(self._integrity_baseline.items()):
            p = Path(path_str)
            if not p.is_file():
                fp = f"missing:{path_str}"
                if fp not in self._tamper_emitted:
                    self._tamper_emitted.add(fp)
                    out.append(
                        self._base_event(
                            monitor_id,
                            "unknown",
                            "tamper_attempt",
                            {
                                "path": path_str[:512],
                                "observation": "monitor_file_missing_or_unreadable",
                            },
                        )
                    )
                continue
            try:
                st = p.stat()
                mt, sz = int(st.st_mtime_ns), int(st.st_size)
            except OSError:
                continue
            if mt != base_mt or sz != base_sz:
                sig = f"{path_str}:{mt}:{sz}"
                if sig not in self._tamper_emitted:
                    self._tamper_emitted.add(sig)
                    out.append(
                        self._base_event(
                            monitor_id,
                            "unknown",
                            "tamper_attempt",
                            {
                                "path": path_str[:512],
                                "observation": "mtime_or_size_changed",
                            },
                        )
                    )
        return out

    def heartbeat_event(self, monitor_id: str) -> dict:
        return self._base_event(
            monitor_id=monitor_id,
            user="system",
            event_type="monitor_heartbeat",
            payload={},
        )


def default_collector_paths() -> tuple[str, str, tuple[str, ...]]:
    if os.name == "nt":
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


def default_integrity_paths() -> tuple[str, ...]:
    """Python sources under `risk_ctf/monitor` for lightweight tamper detection."""
    root = Path(__file__).resolve().parent
    paths: list[str] = []
    for p in sorted(root.glob("*.py")):
        paths.append(str(p))
    return tuple(paths)
