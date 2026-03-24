from __future__ import annotations

import argparse

from risk_ctf.mothership.server import ServerConfig, run_server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Risk-CTF Mothership")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument(
        "--http-dashboard-port",
        type=int,
        default=8080,
        help="Plain HTTP port for /dashboard only; set to 0 to disable",
    )
    parser.add_argument("--db-path", required=True)
    parser.add_argument("--tls-cert", required=True)
    parser.add_argument("--tls-key", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = ServerConfig(
        host=args.host,
        port=args.port,
        db_path=args.db_path,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        http_dashboard_port=args.http_dashboard_port,
    )
    run_server(config)


if __name__ == "__main__":
    main()

