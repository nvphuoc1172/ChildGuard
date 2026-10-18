"""Load the version-controlled website classification used by reports.

The classifier is intentionally read-only: blocking remains a policy concern,
while these categories are used to explain browsing activity to parents.
"""
from __future__ import annotations

import csv
from functools import lru_cache
from pathlib import Path

from app.event_contract import normalize_domain_subject


CATEGORY_DEFINITIONS = (
    {"key": "education", "label": "Giáo dục", "color": "#10b981"},
    {"key": "entertainment", "label": "Giải trí", "color": "#3b82f6"},
    {"key": "social_network", "label": "Mạng xã hội", "color": "#8b5cf6"},
    {"key": "gaming", "label": "Trò chơi", "color": "#f59e0b"},
    {"key": "age_inappropriate", "label": "Không phù hợp lứa tuổi", "color": "#ef4444"},
    {"key": "unclassified", "label": "Chưa phân loại", "color": "#64748b"},
)
CATEGORY_KEYS = frozenset(item["key"] for item in CATEGORY_DEFINITIONS)
DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "website_categories.csv"


@lru_cache(maxsize=1)
def load_domain_categories() -> dict[str, str]:
    """Return normalized registrable-domain -> category mappings."""
    result: dict[str, str] = {}
    with DATA_FILE.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            raw_domain = (row.get("domain") or "").strip().casefold().rstrip(".")
            category = (row.get("category") or "").strip()
            if not raw_domain or category not in CATEGORY_KEYS:
                continue
            # Reserved neutral fixtures retain their full name. Public websites
            # use eTLD+1 so queries for subdomains inherit the same category.
            if raw_domain.endswith((".example", ".test", ".invalid")):
                key = raw_domain
            else:
                key = normalize_domain_subject(raw_domain)
            if key:
                result[key] = category
    return result


def classify_domain(domain: str | None) -> str:
    normalized = normalize_domain_subject(domain or "")
    if not normalized:
        return "unclassified"
    return load_domain_categories().get(normalized, "unclassified")

