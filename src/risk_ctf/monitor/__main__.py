from __future__ import annotations

import argparse

from risk_ctf.monitor.agent import AgentConfig, run_agent
from risk_ctf.monitor.collector import (
    default_collector_paths,
    default_integrity_paths,
)


def parse_args() -> argparse.Namespace:
    default_auth_log, default_secure_log, default_shell_hist = default_collector_paths()
    parser = argparse.ArgumentParser(description="Risk-CTF Monitor")
    parser.add_argument("--mothership-base-url", required=True)
    parser.add_argument("--state-file", required=True)
    parser.add_argument("--source-country", default="Unknown")
    parser.add_argument("--auth-log-path", default=default_auth_log)
    parser.add_argument("--secure-log-path", default=default_secure_log)
    parser.add_argument(
        "--shell-history-path",
        action="append",
        default=list(default_shell_hist),
        help="Can be provided multiple times",
    )
    parser.add_argument("--poll-seconds", type=int, default=5)
    parser.add_argument("--insecure-dev-tls", action="store_true")
    parser.add_argument(
        "--no-integrity-check",
        action="store_true",
        help="Disable baseline checks on Monitor package .py files (tamper_attempt events).",
    )
    parser.add_argument(
        "--integrity-path",
        action="append",
        default=[],
        help="Extra file path to include in integrity baseline (repeatable).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.no_integrity_check:
        integrity: tuple[str, ...] = tuple(args.integrity_path)
    else:
        integrity = tuple(dict.fromkeys(list(default_integrity_paths()) + list(args.integrity_path)))
    run_agent(
        AgentConfig(
            mothership_base_url=args.mothership_base_url,
            state_file=args.state_file,
            source_country=args.source_country,
            auth_log_path=args.auth_log_path,
            secure_log_path=args.secure_log_path,
            shell_history_paths=tuple(args.shell_history_path),
            integrity_paths=integrity,
            poll_seconds=args.poll_seconds,
            insecure_dev_tls=args.insecure_dev_tls,
        )
    )


if __name__ == "__main__":
    main()

