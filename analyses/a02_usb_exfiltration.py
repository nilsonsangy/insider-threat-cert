"""Analysis 2: USB exfiltration (ATT&CK T1052).

r4.2 has no "removable media" flag on file events: a file copy is attributed to
USB when its timestamp falls inside a USB connection window (Connect ->
Disconnect) of the same user and machine. Joins the full device.csv and
file.csv.
"""

from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import defaultdict
from dataclasses import dataclass

import pandas as pd

from insider_threat import loaders as _loaders
from insider_threat import timewin as _timewin

__all__ = ["USBUserSummary", "USBResult", "usb_windows", "run", "main"]


@dataclass(frozen=True)
class USBUserSummary:
    user: str
    connections: int
    off_hours_connections: int
    copies_during_usb: int
    off_hours_copies_during_usb: int


@dataclass(frozen=True)
class USBResult:
    users: list[USBUserSummary]
    total_connections: int
    unclosed_connections: int
    total_copies: int
    copies_during_usb: int


def usb_windows(device: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Pair Connect -> Disconnect per (user, pc) into ``[start, end]`` windows.

    Returns the windows and the number of Connect events that never got a
    Disconnect (those are reported, not guessed).
    """
    df = device.sort_values(["user", "pc", "date"], kind="stable")
    acts = df["activity"].str.strip().str.lower().to_numpy()
    rows: list[tuple] = []
    unclosed = 0
    key = None
    opened = None
    for u, p, d, a in zip(df["user"].to_numpy(), df["pc"].to_numpy(), df["date"], acts):
        if (u, p) != key:
            if opened is not None:
                unclosed += 1
            key, opened = (u, p), None
        if a == "connect":
            if opened is not None:
                unclosed += 1
            opened = d
        elif a == "disconnect" and opened is not None:
            rows.append((u, p, opened, d))
            opened = None
    if opened is not None:
        unclosed += 1
    return pd.DataFrame(rows, columns=["user", "pc", "start", "end"]), unclosed


def run(sources: dict[str, pd.DataFrame], *, work_hours=(7, 19)) -> USBResult:
    device = sources["device"]
    file_df = sources["file"]

    connects = device[device["activity"].str.strip().str.lower() == "connect"]
    conn_count = connects.groupby("user").size()
    off_conn = connects[_timewin.off_hours_mask(connects["date"], work_hours)].groupby("user").size()

    windows, unclosed = usb_windows(device)
    by_key: dict[tuple, tuple[list, list]] = defaultdict(lambda: ([], []))
    for u, p, s, e in windows.itertuples(index=False):
        by_key[(u, p)][0].append(s)
        by_key[(u, p)][1].append(e)

    during = []
    for u, p, d in zip(file_df["user"], file_df["pc"], file_df["date"]):
        entry = by_key.get((u, p))
        if entry is None:
            during.append(False)
            continue
        i = bisect_right(entry[0], d) - 1
        during.append(i >= 0 and entry[1][i] >= d)
    during = pd.Series(during, index=file_df.index)
    usb_copies = file_df[during]
    copy_count = usb_copies.groupby("user").size()
    off_copy = usb_copies[_timewin.off_hours_mask(usb_copies["date"], work_hours)].groupby("user").size()

    summaries = [
        USBUserSummary(
            user=str(u),
            connections=int(conn_count.get(u, 0)),
            off_hours_connections=int(off_conn.get(u, 0)),
            copies_during_usb=int(copy_count.get(u, 0)),
            off_hours_copies_during_usb=int(off_copy.get(u, 0)),
        )
        for u in sorted(set(conn_count.index) | set(copy_count.index))
    ]
    summaries.sort(key=lambda s: (-s.off_hours_copies_during_usb, -s.copies_during_usb, s.user))
    return USBResult(summaries, int(len(connects)), unclosed, int(len(file_df)), int(during.sum()))


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m analyses.a02_usb_exfiltration",
                                description="Analysis 2 (T1052): USB exfiltration.")
    p.add_argument("--top", type=int, default=20, help="How many users to display.")
    args = p.parse_args(argv)

    res = run(_loaders.load_sources())
    users_usb = [s for s in res.users if s.connections > 0]
    users_copy = [s for s in res.users if s.copies_during_usb > 0]
    users_off = [s for s in res.users if s.off_hours_copies_during_usb > 0]

    print("Analysis 2: USB exfiltration (T1052)")
    print("=" * 72)
    print(f"USB connections: {res.total_connections:,} by {len(users_usb)} users "
          f"({res.unclosed_connections:,} without a matching Disconnect)")
    print(f"File copies: {res.total_copies:,} | during a USB connection: {res.copies_during_usb:,}")
    print(f"Users copying during USB: {len(users_copy)} | of those, off hours: {len(users_off)}")
    print()
    print(f"{'user':<10} {'conn':>6} {'off_conn':>8} {'usb_copies':>10} {'off_copies':>10}")
    print("-" * 72)
    for s in res.users[: args.top]:
        print(f"{s.user:<10} {s.connections:>6} {s.off_hours_connections:>8} "
              f"{s.copies_during_usb:>10} {s.off_hours_copies_during_usb:>10}")


if __name__ == "__main__":
    main()
