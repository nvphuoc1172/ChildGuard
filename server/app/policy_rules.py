"""Canonical policy shapes shared by API and Dashboard."""
from __future__ import annotations


def normalize_app_rules(value: object) -> dict:
    """Return the canonical blacklist-only application rules."""
    if isinstance(value, list):
        raw_items = value
    elif isinstance(value, dict):
        raw_items = value.get("blacklist", [])
    else:
        raw_items = []
    if not isinstance(raw_items, list):
        raw_items = []
    items: list = []
    for item in raw_items:
        if item not in items:
            items.append(item)
    return {"mode": "blacklist", "blacklist": items}

