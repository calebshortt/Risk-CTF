"""Fictional world map metadata for the Mothership dashboard (10 host-nations, 2 starter players)."""

from __future__ import annotations

from typing import Any

from risk_ctf.mothership.ledger import COUNTRIES

# Display names only; ledger / events still use COUNTRIES keys (host slot order).
FICTIONAL_NATION_LABELS = [
    "Vespera Reach",
    "Ironhaven Demesne",
    "Sunken Mire",
    "Ember Coast",
    "Frostpeak Marches",
    "Jade Strait",
    "Red Dune Sovereignty",
    "Starfall Archipelago",
    "Obsidian Ridge",
    "Tideglass Republic",
]

# SVG viewBox 0 0 1000 520 — west cluster (indices 0–4), east cluster (5–9).
_NATION_XY: list[tuple[float, float]] = [
    (158, 248),
    (248, 138),
    (198, 368),
    (118, 428),
    (288, 298),
    (712, 242),
    (652, 382),
    (842, 278),
    (732, 128),
    (882, 408),
]

# Land/sea adjacency for map lines (fictional geography).
ADJACENT_PAIRS: list[tuple[str, str]] = [
    ("Canada", "United_States"),
    ("United_States", "United_Kingdom"),
    ("United_States", "Mexico"),
    ("Mexico", "Brazil"),
    ("Brazil", "United_Kingdom"),
    ("Germany", "Japan"),
    ("Germany", "Nigeria"),
    ("Nigeria", "India"),
    ("India", "Japan"),
    ("India", "Australia"),
    ("Japan", "Australia"),
    ("United_Kingdom", "Germany"),
    ("Brazil", "Nigeria"),
]

STARTING_PLAYERS: list[dict[str, str]] = [
    {
        "id": "player_1",
        "label": "Crimson Vanguard",
        "color": "#e63946",
        "nation_key": "Canada",
    },
    {
        "id": "player_2",
        "label": "Azure Warden",
        "color": "#4361ee",
        "nation_key": "Australia",
    },
]


def enrich_dashboard_state(state: dict[str, Any]) -> None:
    """Attach fictional map + starter players to dashboard JSON (mutates state in place)."""
    nations: list[dict[str, Any]] = []
    for i, key in enumerate(COUNTRIES):
        x, y = _NATION_XY[i]
        nations.append(
            {
                "key": key,
                "label": FICTIONAL_NATION_LABELS[i],
                "host_index": i + 1,
                "x": x,
                "y": y,
                "side": "west" if i < 5 else "east",
            }
        )
    state["world"] = {
        "map_name": "The Shattered Meridian",
        "map_subtitle": "Fictional theater — ten host-nations (one Monitor per nation). "
        "Territory stays neutral until activity is ingested.",
        "view_width": 1000,
        "view_height": 520,
        "nations": nations,
        "adjacent_pairs": [{"from": a, "to": b} for a, b in ADJACENT_PAIRS],
        "players": list(STARTING_PLAYERS),
    }
