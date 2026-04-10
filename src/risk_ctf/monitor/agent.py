"""Monitor runtime loop."""

from __future__ import annotations

from dataclasses import dataclass
import socket
import time

from risk_ctf.monitor.client import MonitorClient, MonitorState
from risk_ctf.monitor.collector import CollectorConfig, MonitorCollector


@dataclass
class AgentConfig:
    mothership_base_url: str
    state_file: str
    source_country: str
    auth_log_path: str
    secure_log_path: str
    shell_history_paths: tuple[str, ...]
    integrity_paths: tuple[str, ...]
    poll_seconds: int = 10
    insecure_dev_tls: bool = False


def _hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown-host"


def run_agent(config: AgentConfig) -> None:
    source_host = _hostname()
    client = MonitorClient(
        base_url=config.mothership_base_url,
        state_file=config.state_file,
        allow_insecure_dev_tls=config.insecure_dev_tls,
    )

    state = client.load_state()
    if state is None:
        state = client.register(source_host=source_host, source_country=config.source_country)
        print(f"Registered monitor: {state.monitor_id} ({state.assigned_country})")

    collector = MonitorCollector(
        CollectorConfig(
            auth_log_path=config.auth_log_path,
            secure_log_path=config.secure_log_path,
            shell_history_paths=config.shell_history_paths,
            integrity_paths=config.integrity_paths,
            source_host=source_host,
            source_country=state.assigned_country,
        )
    )
    print("Monitor event loop started")
    while True:
        _poll_once(client, state, collector)
        time.sleep(config.poll_seconds)


def _poll_once(client: MonitorClient, state: MonitorState, collector: MonitorCollector) -> None:
    events = collector.collect_events(monitor_id=state.monitor_id)
    for event in events:
        try:
            result = client.send_event(state, event)
            if result.get("accepted"):
                print(f"event accepted: {event['event_type']}:{event['event_id']}")
        except Exception as exc:  # noqa: BLE001
            print(f"send failed: {exc}")
    hb = collector.heartbeat_event(state.monitor_id)
    try:
        client.send_event(state, hb)
    except Exception as exc:  # noqa: BLE001
        print(f"heartbeat send failed: {exc}")

