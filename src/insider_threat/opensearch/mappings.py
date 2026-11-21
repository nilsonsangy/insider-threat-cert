"""insider_threat.opensearch.mappings: indices, columns and field types."""

from __future__ import annotations

from datetime import datetime

__all__ = ["INDEX_PREFIX", "SOURCES", "DERIVED", "DISCARD", "MAPPINGS", "index_name", "iso_date"]

INDEX_PREFIX = "cert-"

# Sources to ingest and their columns (r4.2 schema).
SOURCES = {
    "logon": ["id", "date", "user", "pc", "activity"],
    "device": ["id", "date", "user", "pc", "activity"],
    "file": ["id", "date", "user", "pc", "filename", "content"],
    "email": ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments", "content"],
    "http": ["id", "date", "user", "pc", "url", "content"],
}
# Derived indices built after the sources.
DERIVED = ("copy-daily", "risk")
# Long-text columns that are not indexed (saves space and time).
DISCARD = {"content"}

_KEYWORD = {"type": "keyword"}
_DATE = {"type": "date"}
_INTEGER = {"type": "integer"}
_BOOLEAN = {"type": "boolean"}

_EVENT_BASE = {"id": _KEYWORD, "user": _KEYWORD, "pc": _KEYWORD, "role": _KEYWORD,
               "date": _DATE, "off_hours": _BOOLEAN}

# Explicit mappings. Fields with the same name have the same type in every index.
MAPPINGS: dict[str, dict[str, dict]] = {
    "logon": {**_EVENT_BASE, "activity": _KEYWORD},
    "device": {**_EVENT_BASE, "activity": _KEYWORD},
    "file": {**_EVENT_BASE, "filename": _KEYWORD},
    "email": {**_EVENT_BASE, "from": _KEYWORD,
              "to": _KEYWORD, "cc": _KEYWORD, "bcc": _KEYWORD,
              "size": _INTEGER, "attachments": _INTEGER, "recipients": _INTEGER},
    # The URL stays in _source only: indexing it would multiply the index size.
    "http": {**_EVENT_BASE, "domain": _KEYWORD, "category": _KEYWORD,
             "url": {"type": "keyword", "index": False, "doc_values": False}},
    "copy-daily": {"user": _KEYWORD, "role": _KEYWORD, "date": _DATE, "copies": _INTEGER},
    "risk": {"user": _KEYWORD, "role": _KEYWORD,
             "off_hours_logon": _BOOLEAN, "off_hours_usb": _BOOLEAN,
             "copy_above_baseline": _BOOLEAN, "job_or_cloud_web": _BOOLEAN,
             "leak_or_spyware_web": _BOOLEAN, "score": _INTEGER,
             "in_answer_key": _BOOLEAN, "scenario": _KEYWORD},
}


def index_name(name: str) -> str:
    """Index of a source or derived target (``http`` -> ``cert-http``)."""
    return INDEX_PREFIX + name


def iso_date(value: str) -> str | None:
    """Convert the CERT 'MM/DD/YYYY HH:MM:SS' date to ISO-8601; None if empty/invalid."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.strptime(value, "%m/%d/%Y %H:%M:%S").isoformat()
    except ValueError:
        return None