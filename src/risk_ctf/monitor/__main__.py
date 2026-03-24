from __future__ import annotations

import argparse

from risk_ctf.monitor.agent import AgentConfig, run_agent
from risk_ctf.monitor.collector import default_collector_paths


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
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_agent(
        AgentConfig(
            mothership_base_url=args.mothership_base_url,
            state_file=args.state_file,
            source_country=args.source_country,
            auth_log_path=args.auth_log_path,
            secure_log_path=args.secure_log_path,
            shell_history_paths=tuple(args.shell_history_path),
            poll_seconds=args.poll_seconds,
            insecure_dev_tls=args.insecure_dev_tls,
        )
    )


if __name__ == "__main__":
    main()

