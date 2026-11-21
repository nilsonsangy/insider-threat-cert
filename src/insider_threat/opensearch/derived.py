"""insider_threat.opensearch.derived: documents of the derived indices.

- ``cert-copy-daily``: file copies per user and day, ``_id`` = ``<user>|<yyyy-mm-dd>``.
- ``cert-risk``: one document per LDAP user with the five signals and the score
  of ``insider_threat.score``, ``_id`` = user. ``in_answer_key`` and ``scenario``
  are for evaluation only and never feed the score.
"""

from __future__ import annotations

import csv

from insider_threat import loaders as _loaders
from insider_threat import score as _score
from insider_threat.opensearch.mappings import iso_date

__all__ = ["copy_daily_documents", "risk_documents", "roles_from_ldap"]


def copy_daily_documents(path, roles: dict[str, str]) -> list[tuple[str, dict]]:
    """Accumulate file copies per (user, day) while reading file.csv."""
    counts: dict[tuple[str, str], int] = {}
    with open(path, "r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            iso = iso_date(row.get("date", ""))
            user = (row.get("user") or "").strip()
            if iso is None or not user:
                continue
            key = (user, iso[:10])
            counts[key] = counts.get(key, 0) + 1
    documents = []
    for (user, day), copies in sorted(counts.items()):
        doc = {"user": user, "date": day, "copies": copies}
        role = roles.get(user)
        if role:
            doc["role"] = role
        documents.append((user + "|" + day, doc))
    return documents


def risk_documents(sources=None, web_users=None) -> list[tuple[str, dict]]:
    """One risk document per LDAP user from the five signals and the score."""
    if sources is None or web_users is None:
        sources, web_users = _score.load_inputs(verbose=False)
    presence = _score.signal_users(sources, web_users=web_users)

    ldap = sources["ldap"]
    roles = dict(zip(ldap["user_id"], ldap["role"]))
    key = sources["answer_key"]
    scenarios: dict[str, str] = {}
    for user, scenario in zip(key["user"], key["scenario"]):
        scenarios.setdefault(user, str(scenario).strip())

    documents = []
    for user in sorted(roles):
        doc: dict = {"user": user}
        if roles[user]:
            doc["role"] = roles[user]
        total = 0
        for signal, weight in _score.WEIGHTS.items():
            present = user in presence[signal]
            doc[signal] = present
            total += weight if present else 0
        doc["score"] = total
        # Evaluation only: not a detection input.
        doc["in_answer_key"] = user in scenarios
        if user in scenarios and scenarios[user]:
            doc["scenario"] = scenarios[user]
        documents.append((user, doc))
    return documents


def roles_from_ldap(data_dir=None) -> dict[str, str]:
    """LDAP roles of the most recent snapshot."""
    ldap = _loaders.load_ldap(data_dir)
    return dict(zip(ldap["user_id"], ldap["role"]))