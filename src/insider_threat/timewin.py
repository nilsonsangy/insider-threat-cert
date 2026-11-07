"""insider_threat.timewin: work-hours windows and logon sessions.

Pure, deterministic module: no network or disk I/O. It operates on
``pandas.Timestamp`` and ``pandas.DataFrame`` objects already loaded by the
loaders.

Key conventions
---------------
- **Work hours** are a window ``(start_hour, end_hour)``, default ``(7, 19)``,
  interpreted as the **half-open** interval ``[start_hour, end_hour)`` in hours
  of the day.
- **Off hours** (``is_off_hours``) is therefore ``hour < start_hour`` **or**
  ``hour >= end_hour``. With the default ``(7, 19)``: 06:59 is off hours, 07:00
  is within hours, 18:59 is within hours, 19:00 is off hours.
- A **session** is the sequential Logon -> Logoff pair for the same
  ``(user, pc)``, represented by the **closed** interval ``[start, end]`` (both
  endpoints belong to the session).
"""

from __future__ import annotations

from bisect import bisect_right

import numpy as np
import pandas as pd

WorkHours = tuple[int, int]  # (start_hour, end_hour), default (7, 19)

DEFAULT_WORK_HOURS: WorkHours = (7, 19)


def is_off_hours(ts: pd.Timestamp, work_hours: WorkHours = DEFAULT_WORK_HOURS) -> bool:
    """Return ``True`` if the time of ``ts`` falls **outside** work hours.

    Work hours are the half-open interval ``[start_hour, end_hour)``. Off hours
    is thus ``hour < start_hour`` or ``hour >= end_hour``. ``NaT``/null raises
    ``ValueError``.
    """
    start, end = work_hours
    ts = pd.Timestamp(ts)
    if ts is pd.NaT or pd.isna(ts):
        raise ValueError("is_off_hours received a null timestamp (NaT).")
    return ts.hour < start or ts.hour >= end


def off_hours_mask(dates: pd.Series, work_hours: WorkHours = DEFAULT_WORK_HOURS) -> pd.Series:
    """Vectorized :func:`is_off_hours` over a datetime Series."""
    start, end = work_hours
    hour = pd.to_datetime(dates).dt.hour
    return (hour < start) | (hour >= end)


def logon_sessions(logon: pd.DataFrame) -> pd.DataFrame:
    """Reduce Logon/Logoff pairs to ``[start, end]`` sessions per ``(user, pc)``.

    For each ``(user, pc)``, events are sorted by ``date`` and paired
    sequentially: each ``Logon`` opens a session and the next ``Logoff`` closes
    it. A ``Logon`` followed by another ``Logon`` keeps the first one open until
    a ``Logoff`` appears; a ``Logoff`` without an open session is discarded.

    Returns columns ``user``, ``pc``, ``start``, ``end``, one row per session,
    sorted by ``user``, ``pc``, ``start``.
    """
    columns = ["user", "pc", "start", "end"]
    required = {"user", "pc", "date", "activity"}
    missing = required - set(logon.columns)
    if missing:
        raise ValueError(
            f"logon_sessions: missing columns in the logon DataFrame: {sorted(missing)}."
        )
    if logon.empty:
        return pd.DataFrame(columns=columns)

    df = logon.loc[:, ["user", "pc", "date", "activity"]].copy()
    df["date"] = pd.to_datetime(df["date"])
    df = df.sort_values(["user", "pc", "date"], kind="stable")

    users = df["user"].to_numpy()
    pcs = df["pc"].to_numpy()
    dates = df["date"].to_numpy()
    acts = df["activity"].astype(str).str.strip().str.lower().to_numpy()

    out_user: list = []
    out_pc: list = []
    out_start: list = []
    out_end: list = []
    key = None
    open_start = None
    for u, p, d, a in zip(users, pcs, dates, acts):
        if (u, p) != key:
            key = (u, p)
            open_start = None
        if a == "logon":
            if open_start is None:
                open_start = d
        elif a == "logoff" and open_start is not None:
            out_user.append(u)
            out_pc.append(p)
            out_start.append(open_start)
            out_end.append(d)
            open_start = None

    return pd.DataFrame({
        "user": out_user,
        "pc": out_pc,
        "start": pd.to_datetime(np.array(out_start, dtype="datetime64[ns]")),
        "end": pd.to_datetime(np.array(out_end, dtype="datetime64[ns]")),
    }, columns=columns)


class SessionIndex:
    """Fast lookup of logon sessions by ``(user, pc)`` and timestamp.

    Sessions of the same ``(user, pc)`` do not overlap (they are produced by
    sequential pairing), so a binary search on the start times finds the only
    candidate session for a timestamp.
    """

    def __init__(self, sessions: pd.DataFrame):
        self._by_key: dict[tuple[str, str], tuple[list, list]] = {}
        if sessions is None or sessions.empty:
            return
        s = sessions.sort_values(["user", "pc", "start"], kind="stable")
        for (user, pc), g in s.groupby(["user", "pc"], sort=False):
            self._by_key[(user, pc)] = (
                list(pd.to_datetime(g["start"])),
                list(pd.to_datetime(g["end"])),
            )

    def find(self, ts: pd.Timestamp, user: str, pc: str):
        """Return the ``(start, end)`` session containing ``ts``, or ``None``."""
        entry = self._by_key.get((user, pc))
        if entry is None:
            return None
        starts, ends = entry
        i = bisect_right(starts, ts) - 1
        if i >= 0 and ends[i] >= ts:
            return starts[i], ends[i]
        return None


def within_session(
    event_ts: pd.Timestamp,
    user: str,
    pc: str,
    sessions: pd.DataFrame,
) -> bool:
    """Return ``True`` if ``event_ts`` falls inside a session of the same user/pc.

    Convenience function for single lookups; for many events build a
    :class:`SessionIndex` once and call :meth:`SessionIndex.find`.
    """
    if sessions is None or sessions.empty:
        return False
    event_ts = pd.Timestamp(event_ts)
    if event_ts is pd.NaT or pd.isna(event_ts):
        raise ValueError("within_session received a null event_ts (NaT).")
    candidates = sessions[(sessions["user"] == user) & (sessions["pc"] == pc)]
    if candidates.empty:
        return False
    start = pd.to_datetime(candidates["start"])
    end = pd.to_datetime(candidates["end"])
    return bool(((start <= event_ts) & (event_ts <= end)).any())
