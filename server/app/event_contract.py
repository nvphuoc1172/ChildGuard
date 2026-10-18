"""Shared validation and normalization for Event Item payloads."""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


EVENT_TYPES = frozenset(
    {
        "app_start",
        "app_stop",
        "domain_query",
        "blocked_app",
        "blocked_domain",
        "quota_warning",
        "locked",
        "unlock_request",
        "override_granted",
    }
)
APP_EVENT_TYPES = frozenset({"app_start", "app_stop", "blocked_app"})
DOMAIN_EVENT_TYPES = frozenset({"domain_query", "blocked_domain"})
SUBJECT_EVENT_TYPES = APP_EVENT_TYPES | DOMAIN_EVENT_TYPES

# Fallback for common multi-label public suffixes when publicsuffix2 is unavailable.
_MULTI_LABEL_SUFFIXES = frozenset(
    {
        "ac.uk", "co.uk", "gov.uk", "org.uk",
        "com.au", "net.au", "org.au",
        "co.jp", "co.kr", "co.nz",
        "com.br", "com.cn", "com.sg",
        "com.vn", "edu.vn", "gov.vn", "net.vn", "org.vn",
    }
)


def normalize_app_subject(value: str) -> str:
    subject = str(value or "").strip().replace("\\", "/").rsplit("/", 1)[-1]
    return subject.casefold()


def normalize_domain_subject(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = (parsed.hostname or "").strip().rstrip(".").casefold()
    if not host:
        return ""
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    try:
        from publicsuffix2 import get_sld  # type: ignore

        return get_sld(host, strict=False) or host
    except ImportError:
        labels = [label for label in host.split(".") if label]
        if len(labels) <= 2:
            return host
        suffix2 = ".".join(labels[-2:])
        return ".".join(labels[-3:]) if suffix2 in _MULTI_LABEL_SUFFIXES else suffix2


def normalize_event_subject(event_type: str, subject: str | None) -> str | None:
    if event_type in APP_EVENT_TYPES:
        return normalize_app_subject(subject or "")
    if event_type in DOMAIN_EVENT_TYPES:
        return normalize_domain_subject(subject or "")
    return None
