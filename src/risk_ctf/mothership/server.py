"""Stdlib HTTPS server for monitor registration, ingest, and dashboard."""

from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
import threading
import time
from typing import Any
from urllib.parse import urlparse

from risk_ctf.common.auth import verify_signature
from risk_ctf.common.contracts import (
    DASHBOARD_PATH,
    EVENTS_PATH,
    HEADER_MONITOR_ID,
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TS,
    MAX_CLOCK_SKEW_SECONDS,
    NONCE_TTL_SECONDS,
    REGISTER_PATH,
)
from risk_ctf.common.schema import EventEnvelope, SchemaError
from risk_ctf.mothership.ledger import Ledger
from risk_ctf.mothership.world_map import enrich_dashboard_state


@dataclass
class ServerConfig:
    host: str
    port: int
    db_path: str
    tls_cert: str
    tls_key: str
    # If > 0, serve dashboard (and read-only state) on plain HTTP on this port. API stays on HTTPS only.
    http_dashboard_port: int = 0


class MothershipServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        handler_cls: type[BaseHTTPRequestHandler],
        ledger: Ledger,
        *,
        allow_api: bool = True,
    ) -> None:
        super().__init__(server_address, handler_cls)
        self.ledger = ledger
        self.allow_api = allow_api


class RequestHandler(BaseHTTPRequestHandler):
    server: MothershipServer

    def _json_body(self) -> dict[str, Any]:
        size = int(self.headers.get("Content-Length", "0"))
        if size <= 0:
            raise ValueError("empty body")
        raw = self.rfile.read(size)
        return json.loads(raw.decode("utf-8"))

    def _write_json(self, code: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _write_html(self, code: int, html: str) -> None:
        encoded = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if not self.server.allow_api:
            if path == "/":
                self.send_response(302)
                self.send_header("Location", DASHBOARD_PATH)
                self.end_headers()
                return
            allowed_http = (DASHBOARD_PATH, "/api/v1/dashboard/state", "/healthz")
            if path not in allowed_http:
                self._write_json(404, {"error": "not found"})
                return
        if path == DASHBOARD_PATH:
            state = self.server.ledger.dashboard_state()
            enrich_dashboard_state(state)
            self._write_html(200, render_dashboard_html(state))
            return
        if path == "/api/v1/dashboard/state":
            state = self.server.ledger.dashboard_state()
            enrich_dashboard_state(state)
            self._write_json(200, state)
            return
        if path == "/healthz":
            self._write_json(200, {"ok": True})
            return
        self._write_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self.server.allow_api:
            self._write_json(403, {"error": "api is only available over https"})
            return
        path = urlparse(self.path).path
        if path == REGISTER_PATH:
            self._handle_register()
            return
        if path == EVENTS_PATH:
            self._handle_events()
            return
        self._write_json(404, {"error": "not found"})

    def _handle_register(self) -> None:
        try:
            body = self._json_body()
            fingerprint = str(body["fingerprint"])
            source_host = str(body["source_host"])
            source_country = str(body["source_country"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self._write_json(400, {"error": "invalid registration payload"})
            return
        result = self.server.ledger.register_monitor(
            fingerprint=fingerprint,
            source_host=source_host,
            source_country=source_country,
            created_at_ts=int(time.time()),
        )
        self._write_json(201, result)

    def _handle_events(self) -> None:
        monitor_id = self.headers.get(HEADER_MONITOR_ID)
        ts_raw = self.headers.get(HEADER_TS)
        nonce = self.headers.get(HEADER_NONCE)
        signature = self.headers.get(HEADER_SIGNATURE)
        if not monitor_id or not ts_raw or not nonce or not signature:
            self._write_json(401, {"error": "missing auth headers"})
            return
        try:
            ts = int(ts_raw)
        except ValueError:
            self._write_json(401, {"error": "bad timestamp"})
            return

        now = int(time.time())
        if abs(now - ts) > MAX_CLOCK_SKEW_SECONDS:
            self._write_json(401, {"error": "timestamp out of range"})
            return
        if self.server.ledger.nonce_seen(monitor_id, nonce):
            self._write_json(401, {"error": "nonce replay detected"})
            return
        secret = self.server.ledger.get_monitor_secret(monitor_id)
        if not secret:
            self._write_json(401, {"error": "unknown monitor"})
            return

        try:
            body = self._json_body()
        except (ValueError, json.JSONDecodeError):
            self._write_json(400, {"error": "invalid json"})
            return

        if not verify_signature(
            secret=secret,
            method="POST",
            path=EVENTS_PATH,
            payload=body,
            ts=ts,
            nonce=nonce,
            signature_b64=signature,
        ):
            self._write_json(401, {"error": "bad signature"})
            return
        try:
            validated = EventEnvelope.validate(body).to_dict()
        except SchemaError as exc:
            self._write_json(400, {"error": str(exc)})
            return
        if validated["monitor_id"] != monitor_id:
            self._write_json(401, {"error": "monitor_id mismatch"})
            return

        self.server.ledger.remember_nonce(
            monitor_id=monitor_id,
            nonce=nonce,
            ts=ts,
            nonce_ttl=NONCE_TTL_SECONDS,
        )
        self.server.ledger.record_event(validated)
        self._write_json(202, {"accepted": True})

    def log_message(self, fmt: str, *args: Any) -> None:
        # Intentionally keep logs concise for least disclosure.
        print(f"[mothership] {self.address_string()} {fmt % args}")


def render_dashboard_html(state: dict[str, Any]) -> str:
    state_json = json.dumps(state, ensure_ascii=True)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Risk-CTF Dashboard</title>
  <style>
    :root {{
      --bg: #0d1b2a;
      --panel: #1b263b;
      --text: #e0e1dd;
      --muted: #778da9;
      --sea: #1d3557;
      --neutral: #415a77;
    }}
    body {{
      font-family: "Segoe UI", Arial, sans-serif;
      margin: 0;
      background: var(--bg);
      color: var(--text);
    }}
    header {{
      padding: 1rem 1.25rem;
      border-bottom: 1px solid #415a77;
    }}
    header h1 {{ margin: 0 0 0.35rem 0; font-size: 1.35rem; }}
    header p {{ margin: 0; color: var(--muted); font-size: 0.9rem; max-width: 52rem; }}
    main {{ padding: 1rem 1.25rem 2rem; }}
    .map-wrap {{
      background: var(--panel);
      border-radius: 12px;
      border: 1px solid #415a77;
      padding: 0.75rem;
      margin-bottom: 1.25rem;
      max-width: 1000px;
    }}
    .map-wrap h2 {{
      margin: 0 0 0.5rem 0;
      font-size: 1.05rem;
      font-weight: 600;
    }}
    .map-wrap .sub {{ color: var(--muted); font-size: 0.8rem; margin-bottom: 0.5rem; }}
    svg.world-map {{ display: block; width: 100%; height: auto; border-radius: 8px; background: linear-gradient(180deg, #0b1321 0%, var(--sea) 45%, #0b1321 100%); }}
    .legend {{
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
      margin-top: 0.75rem;
      font-size: 0.85rem;
    }}
    .legend-item {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
      background: #0b1321;
      padding: 0.35rem 0.65rem;
      border-radius: 8px;
      border: 1px solid #415a77;
    }}
    .legend-swatch {{
      width: 14px;
      height: 14px;
      border-radius: 50%;
      border: 2px solid rgba(255,255,255,0.35);
    }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 10px; }}
    .country {{ border: 1px solid #415a77; border-radius: 8px; padding: 8px; background: var(--panel); }}
    .chip {{ display: inline-block; width: 10px; height: 10px; border-radius: 999px; margin-right: 4px; }}
    #popup {{
      position: fixed;
      top: 16px;
      right: 16px;
      background: #111;
      color: #fff;
      padding: 10px 14px;
      border-radius: 6px;
      display: none;
      z-index: 20;
    }}
    h3.section {{ font-size: 1rem; margin: 1.25rem 0 0.5rem; }}
    .feed-wrap {{ max-width: 1000px; overflow-x: auto; background: var(--panel); border: 1px solid #415a77; border-radius: 10px; }}
    table.feed {{ width: 100%; border-collapse: collapse; font-size: 0.8rem; }}
    table.feed th, table.feed td {{ padding: 6px 10px; text-align: left; border-bottom: 1px solid #415a77; }}
    table.feed th {{ color: var(--muted); font-weight: 600; }}
  </style>
</head>
<body>
  <header>
    <h1>Risk-CTF Mothership</h1>
    <p id="map-title"></p>
  </header>
  <main>
    <div class="map-wrap">
      <h2>World map</h2>
      <p class="sub" id="map-sub"></p>
      <svg class="world-map" id="world-svg" viewBox="0 0 1000 520" role="img" aria-label="Fictional world map"></svg>
      <div class="legend" id="player-legend"></div>
    </div>
    <div id="popup"></div>
    <h3 class="section">Activity by host-nation (from ingested events)</h3>
    <p style="color:var(--muted);font-size:0.85rem;margin:0 0 0.75rem;">Empty until Monitors report activity. Ledger keys match host slots below.</p>
    <div id="countries" class="grid"></div>
    <h3 class="section">Movements</h3>
    <ul id="moves"></ul>
    <h3 class="section">Recent activity</h3>
    <p style="color:var(--muted);font-size:0.85rem;margin:0 0 0.5rem;">Latest ingested events; summary shows the command or context when available.</p>
    <div class="feed-wrap">
      <table class="feed" aria-label="Recent activity">
        <thead><tr><th>Time</th><th>Actor</th><th>Nation</th><th>Summary</th></tr></thead>
        <tbody id="activity-feed"></tbody>
      </table>
    </div>
  </main>
  <script>
    const initialState = {state_json};
    const svg = document.getElementById("world-svg");
    const leg = document.getElementById("player-legend");
    const feedBody = document.getElementById("activity-feed");
    const countriesEl = document.getElementById("countries");
    const movesEl = document.getElementById("moves");
    const popup = document.getElementById("popup");
    const mapTitleEl = document.getElementById("map-title");
    const mapSubEl = document.getElementById("map-sub");
    const popupSeen = new Set();
    const ns = "http://www.w3.org/2000/svg";

    function renderDashboard(state) {{
      const w = state.world;
      const vw = w.view_width;
      const vh = w.view_height;
      svg.setAttribute("viewBox", `0 0 ${{vw}} ${{vh}}`);
      mapTitleEl.textContent = w.map_name + " — ten host-nations, two starting players (opposite shores).";
      mapSubEl.textContent = w.map_subtitle;

      const byKey = {{}};
      w.nations.forEach((n) => {{ byKey[n.key] = n; }});

      while (svg.firstChild) svg.removeChild(svg.firstChild);

    // Faint fictional landmasses (west / east) — decorative only
    const landW = document.createElementNS(ns, "path");
    landW.setAttribute("fill", "rgba(141, 153, 174, 0.12)");
    landW.setAttribute("stroke", "none");
    landW.setAttribute("d", "M40,120 C120,80 200,100 280,180 C300,260 260,380 180,440 C100,460 50,380 40,260 Z");
    svg.appendChild(landW);
    const landE = document.createElementNS(ns, "path");
    landE.setAttribute("fill", "rgba(141, 153, 174, 0.12)");
    landE.setAttribute("stroke", "none");
    landE.setAttribute("d", "M620,100 C720,60 820,80 920,160 C960,240 940,400 860,450 C760,480 640,420 600,300 Z");
    svg.appendChild(landE);

    // Adjacency lines
    const linkG = document.createElementNS(ns, "g");
    linkG.setAttribute("stroke", "rgba(224, 225, 221, 0.18)");
    linkG.setAttribute("stroke-width", "2");
    w.adjacent_pairs.forEach((e) => {{
      const a = byKey[e.from];
      const b = byKey[e.to];
      if (!a || !b) return;
      const line = document.createElementNS(ns, "line");
      line.setAttribute("x1", a.x);
      line.setAttribute("y1", a.y);
      line.setAttribute("x2", b.x);
      line.setAttribute("y2", b.y);
      linkG.appendChild(line);
    }});
    svg.appendChild(linkG);

    // Activity overlay: nation -> list of user colors from state
    const activity = {{}};
    (state.countries || []).forEach((c) => {{
      activity[c.country] = c.colors || [];
    }});

    const nationG = document.createElementNS(ns, "g");
    w.nations.forEach((n) => {{
      const g = document.createElementNS(ns, "g");
      g.setAttribute("transform", `translate(${{n.x}}, ${{n.y}})`);

      const cols = activity[n.key] || [];
      const r = 26;
      const base = document.createElementNS(ns, "circle");
      base.setAttribute("r", r);
      base.setAttribute("stroke", "#e0e1dd");
      base.setAttribute("stroke-width", "2");
      if (cols.length === 0) {{
        base.setAttribute("fill", "#2b3e5a");
        base.setAttribute("opacity", "0.55");
      }} else if (cols.length === 1) {{
        base.setAttribute("fill", cols[0]);
        base.setAttribute("opacity", "0.95");
      }} else {{
        base.setAttribute("fill", "#1a2332");
        base.setAttribute("opacity", "0.92");
      }}
      g.appendChild(base);
      if (cols.length > 1) {{
        const rim = r + 7;
        cols.forEach((col, i) => {{
          const angle = (2 * Math.PI * i) / cols.length - Math.PI / 2;
          const dot = document.createElementNS(ns, "circle");
          dot.setAttribute("cx", (Math.cos(angle) * rim).toFixed(2));
          dot.setAttribute("cy", (Math.sin(angle) * rim).toFixed(2));
          dot.setAttribute("r", "7");
          dot.setAttribute("fill", col);
          dot.setAttribute("stroke", "#fff");
          dot.setAttribute("stroke-width", "1.5");
          g.appendChild(dot);
        }});
      }}

      const t = document.createElementNS(ns, "text");
      t.setAttribute("y", r + 18);
      t.setAttribute("text-anchor", "middle");
      t.setAttribute("fill", "#e0e1dd");
      t.setAttribute("font-size", "11");
      t.setAttribute("font-weight", "600");
      t.textContent = n.label;
      g.appendChild(t);

      const t2 = document.createElementNS(ns, "text");
      t2.setAttribute("y", r + 32);
      t2.setAttribute("text-anchor", "middle");
      t2.setAttribute("fill", "#778da9");
      t2.setAttribute("font-size", "9");
      t2.textContent = "Host " + n.host_index + " (" + n.key.replace(/_/g, " ") + ")";
      g.appendChild(t2);

      nationG.appendChild(g);
    }});
    svg.appendChild(nationG);

    // Starting players on opposite sides (west / east anchors)
    const playersG = document.createElementNS(ns, "g");
    w.players.forEach((p, idx) => {{
      const n = byKey[p.nation_key];
      if (!n) return;
      const g = document.createElementNS(ns, "g");
      const ox = idx === 0 ? -18 : 18;
      const oy = -22;
      g.setAttribute("transform", `translate(${{n.x + ox}}, ${{n.y + oy}})`);
      const ring = document.createElementNS(ns, "circle");
      ring.setAttribute("r", "10");
      ring.setAttribute("fill", p.color);
      ring.setAttribute("stroke", "#fff");
      ring.setAttribute("stroke-width", "2");
      g.appendChild(ring);
      const pt = document.createElementNS(ns, "text");
      pt.setAttribute("y", "-14");
      pt.setAttribute("text-anchor", "middle");
      pt.setAttribute("fill", "#e0e1dd");
      pt.setAttribute("font-size", "10");
      pt.setAttribute("font-weight", "700");
      pt.textContent = (idx + 1);
      g.appendChild(pt);
      playersG.appendChild(g);
    }});
    svg.appendChild(playersG);

    leg.replaceChildren();
    w.players.forEach((p) => {{
      const div = document.createElement("div");
      div.className = "legend-item";
      div.innerHTML = `<span class="legend-swatch" style="background:${{p.color}}"></span><span><strong>${{p.label}}</strong> — start: <em>${{byKey[p.nation_key].label}}</em> (${{byKey[p.nation_key].side}} shore)</span>`;
      leg.appendChild(div);
    }});
    (state.players_legend || []).forEach((pl) => {{
      const div = document.createElement("div");
      div.className = "legend-item";
      div.innerHTML = `<span class="legend-swatch" style="background:${{pl.color}}"></span><span><strong>${{pl.label}}</strong> — detected from events</span>`;
      leg.appendChild(div);
    }});

    feedBody.replaceChildren();
    (state.activity_feed || []).forEach((row) => {{
      const tr = document.createElement("tr");
      const cmd = (row.executed_command || "").trim();
      const summaryText = cmd || (row.summary || "");
      const tds = [row.ts || "", row.actor_user || "", row.source_country || "", summaryText];
      tr.innerHTML = "<td>" + tds.map((c) => String(c).replace(/&/g,"&amp;").replace(/</g,"&lt;")).join("</td><td>") + "</td>";
      feedBody.appendChild(tr);
    }});

    countriesEl.replaceChildren();

    (state.countries || []).forEach((country) => {{
      const node = document.createElement("div");
      node.className = "country";
      const chips = (country.colors || []).map(c => `<span class="chip" style="background:${{c}}"></span>`).join("");
      node.innerHTML = `<strong>${{country.country}}</strong><div>${{chips}}</div><div>${{country.users.join(", ") || "No activity yet"}}</div>`;
      countriesEl.appendChild(node);

      country.users.forEach(user => {{
        const key = `${{user}}:${{country.country}}`;
        if (!popupSeen.has(key)) {{
          popupSeen.add(key);
          popup.textContent = `${{user}} captured ${{country.country}}`;
          popup.style.display = "block";
          setTimeout(() => {{ popup.style.display = "none"; }}, 3000);
        }}
      }});
    }});

    movesEl.replaceChildren();
    (state.moves || []).forEach((move) => {{
      const li = document.createElement("li");
      li.textContent = `${{move.user}} moved: ${{move.from}} -> ${{move.to}}`;
      li.style.color = move.color;
      movesEl.appendChild(li);
    }});
    }}

    renderDashboard(initialState);
    setInterval(async () => {{
      try {{
        const res = await fetch("/api/v1/dashboard/state");
        if (!res.ok) return;
        renderDashboard(await res.json());
      }} catch (err) {{}}
    }}, 5000);
  </script>
</body>
</html>"""


def run_server(config: ServerConfig) -> None:
    ledger = Ledger(config.db_path)
    if config.http_dashboard_port > 0:
        http_server = MothershipServer(
            (config.host, config.http_dashboard_port),
            RequestHandler,
            ledger,
            allow_api=False,
        )
        http_thread = threading.Thread(target=http_server.serve_forever, name="mothership-http", daemon=True)
        http_thread.start()
        print(
            f"Mothership dashboard (HTTP): http://{config.host}:{config.http_dashboard_port}{DASHBOARD_PATH}"
        )
    server = MothershipServer((config.host, config.port), RequestHandler, ledger, allow_api=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(config.tls_cert, config.tls_key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f"Mothership API (HTTPS): https://{config.host}:{config.port}")
    server.serve_forever()

