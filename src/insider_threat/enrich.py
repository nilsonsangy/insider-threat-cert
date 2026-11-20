"""insider_threat.enrich: derived fields added to each event before indexing.

Pure, deterministic module: no network or disk I/O.

Derived fields by source
------------------------
- All sources: ``off_hours`` (boolean) and ``role`` (LDAP role of the user;
  omitted when the user is not in the LDAP data).
- ``cert-email``: ``to``, ``cc`` and ``bcc`` as lists of addresses,
  ``recipients``, ``size`` and ``attachments`` as integers.
- ``cert-http``: ``domain`` (host of the URL) and ``category`` (omitted when
  the host belongs to no suspicious category).

``off_hours`` is computed on the date as recorded, without time zone
conversion, with the same rule as :func:`insider_threat.timewin.is_off_hours`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

import pandas as pd

from insider_threat.domains import category_of_host, host_of
from insider_threat.mass_email import recipient_count, split_addresses
from insider_threat.timewin import DEFAULT_WORK_HOURS, WorkHours, is_off_hours


@dataclass(frozen=True)
class EnrichContext:
    """Lookup data needed to enrich rows.

    ``roles`` maps a user id to the role in the most recent LDAP snapshot.
    ``host_category`` maps a host to its suspicious category, or ``None``.
    """

    roles: Mapping[str, str]
    host_category: Callable[[str], str | None] = category_of_host


def off_hours(date_iso: str, work_hours: WorkHours = DEFAULT_WORK_HOURS) -> bool:
    """Return True when the time of an ISO-8601 date is outside work hours."""
    return is_off_hours(pd.Timestamp(date_iso), work_hours)


def _to_int(value: object) -> int:
    """Convert a CSV value to an integer, treating empty values as zero."""
    if value is None or value == "":
        return 0
    return int(float(value))


def enrich_row(source: str, doc: dict, ctx: EnrichContext) -> dict:
    """Return a new document with the derived fields of ``source``.

    The input ``doc`` is not modified.
    """
    out = dict(doc)
    out["off_hours"] = off_hours(str(doc["date"]))

    role = ctx.roles.get(str(doc.get("user", "")))
    if role:
        out["role"] = role

    if source == "cert-email":
        to, cc, bcc = (str(doc.get(k) or "") for k in ("to", "cc", "bcc"))
        out["to"] = split_addresses(to)
        out["cc"] = split_addresses(cc)
        out["bcc"] = split_addresses(bcc)
        out["recipients"] = recipient_count(to, cc, bcc)
        out["size"] = _to_int(doc.get("size"))
        out["attachments"] = _to_int(doc.get("attachments"))
    elif source == "cert-http":
        domain = host_of(str(doc.get("url") or ""))
        out["domain"] = domain
        category = ctx.host_category(domain)
        if category:
            out["category"] = category

    return out
