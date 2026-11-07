"""insider_threat.score: additive risk score per signal type (CERT r4.2).

For each user, sums weights for the PRESENCE of each signal type:

    off-hours logon ........................ +1
    off-hours USB in own session ........... +2
    copies above 3x role baseline .......... +3
    job site / cloud storage browsing ...... +1   (common, weak)
    leak site / spyware browsing ........... +3   (rare, specific)

Weights are fixed a priori by how specific each behavior is; they are not fitted
to the answer key. The web signals come from the full ``http.csv``, which is
streamed by ``analyses.a01_web_browsing`` and passed in as users per category.
The other sources come from ``insider_threat.loaders.load_sources``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from insider_threat import baseline as _baseline
from insider_threat import timewin as _timewin

__all__ = ["WEIGHTS", "SuspectScore", "signal_users", "score_by_user"]

WEIGHTS: dict[str, int] = {
    "off_hours_logon": 1,
    "off_hours_usb": 2,
    "copy_above_baseline": 3,
    "job_or_cloud_web": 1,
    "leak_or_spyware_web": 3,
}


@dataclass(frozen=True)
class SuspectScore:
    user: str
    score: int
    signals: dict[str, int] = field(default_factory=dict)


def _off_hours_logon(logon: pd.DataFrame, work_hours) -> set[str]:
    """Users with at least one Logon event outside work hours."""
    logons = logon[logon["activity"].str.strip().str.lower() == "logon"]
    return set(logons.loc[_timewin.off_hours_mask(logons["date"], work_hours), "user"])


def _off_hours_usb(device: pd.DataFrame, logon: pd.DataFrame, work_hours) -> set[str]:
    """Users with an off-hours USB Connect inside one of their own logon sessions."""
    connects = device[device["activity"].str.strip().str.lower() == "connect"]
    connects = connects[_timewin.off_hours_mask(connects["date"], work_hours)]
    index = _timewin.SessionIndex(_timewin.logon_sessions(logon))
    users: set[str] = set()
    for user, pc, ts in zip(connects["user"], connects["pc"], connects["date"]):
        if user not in users and index.find(ts, user, pc) is not None:
            users.add(user)
    return users


def _copy_above_baseline(file_df: pd.DataFrame, ldap_df: pd.DataFrame,
                         min_factor: float) -> set[str]:
    """Users whose mean copies/day exceed ``min_factor`` x their role baseline."""
    individual = _baseline.individual_baseline(file_df)
    peer = _baseline.peer_group_baseline(file_df, ldap_df)
    role = ldap_df.drop_duplicates("user_id").set_index("user_id")["role"]
    base = individual.index.map(role).map(peer)
    above = individual[(base > 0) & (individual.to_numpy() > base * min_factor)]
    return set(above.index)


def signal_users(
    sources: dict[str, pd.DataFrame],
    *,
    web_users: dict[str, set[str]] | None = None,
    work_hours: tuple[int, int] = (7, 19),
    copy_factor: float = 3.0,
) -> dict[str, set[str]]:
    """Return, per signal type, the set of users that present the signal.

    ``web_users`` maps a web category (see ``insider_threat.domains``) to the
    users that visited it; ``None`` means the web signals are not counted.
    """
    web = web_users or {}
    return {
        "off_hours_logon": _off_hours_logon(sources["logon"], work_hours),
        "off_hours_usb": _off_hours_usb(sources["device"], sources["logon"], work_hours),
        "copy_above_baseline": _copy_above_baseline(sources["file"], sources["ldap"], copy_factor),
        "job_or_cloud_web": set(web.get("job_site", ())) | set(web.get("cloud_storage", ())),
        "leak_or_spyware_web": set(web.get("leak_site", ())) | set(web.get("spyware", ())),
    }


def score_by_user(
    sources: dict[str, pd.DataFrame],
    *,
    web_users: dict[str, set[str]] | None = None,
    work_hours: tuple[int, int] = (7, 19),
    copy_factor: float = 3.0,
) -> list[SuspectScore]:
    """Compute the risk score per user (signal presence x weight), highest first."""
    presence = signal_users(sources, web_users=web_users, work_hours=work_hours,
                            copy_factor=copy_factor)
    users: set[str] = set().union(*presence.values())
    out: list[SuspectScore] = []
    for u in users:
        signals = {t: WEIGHTS[t] for t, members in presence.items() if u in members}
        out.append(SuspectScore(user=u, score=sum(signals.values()), signals=signals))
    out.sort(key=lambda s: (-s.score, s.user))
    return out
