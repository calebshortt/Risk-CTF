from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from risk_ctf.monitor.collector import (
    CollectorConfig,
    MonitorCollector,
    actor_user_from_shell_history_path,
)


class CollectorTests(unittest.TestCase):
    def test_integrity_emits_once_on_change(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write("# v1 short\n")
            path = f.name
        try:
            cfg = CollectorConfig(
                auth_log_path="/nonexistent_auth_xxx",
                secure_log_path="/nonexistent_sec_xxx",
                shell_history_paths=(),
                integrity_paths=(path,),
                source_host="h1",
                source_country="Canada",
            )
            col = MonitorCollector(cfg)
            self.assertEqual(col.collect_events("mon_t"), [])
            Path(path).write_text("# v2 much longer content for size delta\n", encoding="utf-8")
            events = col.collect_events("mon_t")
            self.assertTrue(any(e["event_type"] == "tamper_attempt" for e in events))
            again = col.collect_events("mon_t")
            self.assertFalse(any(e["event_type"] == "tamper_attempt" for e in again))
        finally:
            Path(path).unlink(missing_ok=True)

    def test_shell_wget_is_tool_download_not_plain_command(self) -> None:
        cfg = CollectorConfig(
            auth_log_path="/nonexistent",
            secure_log_path="/nonexistent",
            shell_history_paths=(),
            integrity_paths=(),
            source_host="h",
            source_country="X",
        )
        col = MonitorCollector(cfg)
        line = "wget https://example.com/tool.gz\n"
        events = col._parse_shell_line(line, "m1", "alice")  # noqa: SLF001
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "tool_download")
        self.assertEqual(events[0]["actor_user"], "alice")

    def test_shell_etc_passwd_emits_sensitive_file_access(self) -> None:
        cfg = CollectorConfig(
            auth_log_path="/nonexistent",
            secure_log_path="/nonexistent",
            shell_history_paths=(),
            integrity_paths=(),
            source_host="h",
            source_country="X",
        )
        col = MonitorCollector(cfg)
        events = col._parse_shell_line("cat /etc/passwd\n", "m1", "bob")  # noqa: SLF001
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "sensitive_file_access")
        self.assertEqual(events[0]["actor_user"], "bob")
        self.assertEqual(events[0]["payload"]["path"], "/etc/passwd")
        self.assertIn("/etc/passwd", events[0]["payload"]["command_line"])

    def test_auth_line_etc_passwd_emits_sensitive_file_access(self) -> None:
        cfg = CollectorConfig(
            auth_log_path="/nonexistent",
            secure_log_path="/nonexistent",
            shell_history_paths=(),
            integrity_paths=(),
            source_host="h",
            source_country="Canada",
        )
        col = MonitorCollector(cfg)
        line = "Mar 23 12:00:00 sudo: user ran cat /etc/passwd\n"
        ev = col._parse_auth_line(line, "m1")  # noqa: SLF001
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "sensitive_file_access")

    def test_etc_passwd_suffix_not_matched(self) -> None:
        cfg = CollectorConfig(
            auth_log_path="/nonexistent",
            secure_log_path="/nonexistent",
            shell_history_paths=(),
            integrity_paths=(),
            source_host="h",
            source_country="X",
        )
        col = MonitorCollector(cfg)
        events = col._parse_shell_line("diff /etc/passwd.bak /tmp/x\n", "m1", "carol")  # noqa: SLF001
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "command_executed")
        self.assertEqual(events[0]["actor_user"], "carol")
        self.assertEqual(events[0]["payload"]["executed_command"], events[0]["payload"]["command_line"])

    def test_shell_plain_line_is_command_executed(self) -> None:
        cfg = CollectorConfig(
            auth_log_path="/nonexistent",
            secure_log_path="/nonexistent",
            shell_history_paths=(),
            integrity_paths=(),
            source_host="h",
            source_country="X",
        )
        col = MonitorCollector(cfg)
        events = col._parse_shell_line("echo hello\n", "m1", "dave")  # noqa: SLF001
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "command_executed")
        self.assertEqual(events[0]["actor_user"], "dave")
        self.assertIn("echo", events[0]["payload"]["command_line"])
        self.assertEqual(events[0]["payload"]["executed_command"], events[0]["payload"]["command_line"])

    def test_actor_from_shell_history_path(self) -> None:
        if os.name == "nt":
            self.assertEqual(
                actor_user_from_shell_history_path(r"C:\Users\SomeUser\Documents\history.txt"),
                "SomeUser",
            )
        else:
            self.assertEqual(actor_user_from_shell_history_path("/home/bob/.bash_history"), "bob")
            self.assertEqual(actor_user_from_shell_history_path("/root/.bash_history"), "root")

    def test_auth_session_closed_emits_session_terminate(self) -> None:
        cfg = CollectorConfig(
            auth_log_path="/nonexistent",
            secure_log_path="/nonexistent",
            shell_history_paths=(),
            integrity_paths=(),
            source_host="h",
            source_country="Canada",
        )
        col = MonitorCollector(cfg)
        line = "Mar 23 12:00:00 sshd: session closed for user alice\n"
        ev = col._parse_auth_line(line, "m1")  # noqa: SLF001
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "session_terminate")
        self.assertEqual(ev["actor_user"], "alice")
        self.assertEqual(ev["payload"]["target_user"], "alice")

    def test_auth_reboot_line_emits_host_reboot(self) -> None:
        cfg = CollectorConfig(
            auth_log_path="/nonexistent",
            secure_log_path="/nonexistent",
            shell_history_paths=(),
            integrity_paths=(),
            source_host="h",
            source_country="Canada",
        )
        col = MonitorCollector(cfg)
        line = "Mar 23 12:00:00 systemd-logind: system is rebooting\n"
        ev = col._parse_auth_line(line, "m1")  # noqa: SLF001
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "host_reboot")
        self.assertEqual(ev["actor_user"], "system")


if __name__ == "__main__":
    unittest.main()
