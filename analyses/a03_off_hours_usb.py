"""Analysis 3: off-hours USB cross-referenced with logon (ATT&CK T1078 + T1052).

USB connections outside work hours that fall inside a real logon session of the
same user and machine (strong signal: it was the user themselves, logged in).
Joins the full device.csv and logon.csv.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

import pandas as pd

from insider_threat import loaders as _loaders
from insider_threat import timewin as _timewin

__all__ = ["OffHoursUSBEvent", "parse_work_hours", "run", "main"]


@dataclass(frozen=True)
class OffHoursUSBEvent:
    user: str
    pc: str
    usb_ts: pd.Timestamp
    session_start: pd.Timestamp | None
    session_end: pd.Timestamp | None

    @property
    def strong(self) -> bool:
        return self.session_start is not None


def parse_work_hours(text: str) -> tuple[int, int]:
    parts = text.split("-")
    try:
        a, b = int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        raise argparse.ArgumentTypeError(f"--work-hours expects HOUR-HOUR (e.g. 7-19); got {text!r}.")
    if len(parts) != 2 or not (0 <= a < b <= 24):
        raise argparse.ArgumentTypeError(f"--work-hours expects 0 <= START < END <= 24; got {text!r}.")
    return (a, b)


def run(sources: dict[str, pd.DataFrame], work_hours=(7, 19)) -> list[OffHoursUSBEvent]:
    device = sources["device"]
    index = _timewin.SessionIndex(_timewin.logon_sessions(sources["logon"]))
    connects = device[device["activity"].str.strip().str.lower() == "connect"]
    connects = connects[_timewin.off_hours_mask(connects["date"], work_hours)]
    out: list[OffHoursUSBEvent] = []
    for user, pc, ts in zip(connects["user"], connects["pc"], connects["date"]):
        hit = index.find(ts, user, pc)
        start, end = hit if hit is not None else (None, None)
        out.append(OffHoursUSBEvent(user, pc, ts, start, end))
    out.sort(key=lambda o: (o.usb_ts, o.user, o.pc))
    return out


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m analyses.a03_off_hours_usb",
                                description="Analysis 3 (T1078+T1052): off-hours USB x logon.")
    p.add_argument("--work-hours", type=parse_work_hours, default=(7, 19), metavar="START-END")
    p.add_argument("--top", type=int, default=20, help="How many users to display.")
    args = p.parse_args(argv)

    events = run(_loaders.load_sources(), work_hours=args.work_hours)
    strong = [e for e in events if e.strong]
    per_user = pd.Series([e.user for e in strong]).value_counts() if strong else pd.Series(dtype=int)

    print(f"Analysis 3: off-hours USB x logon (work hours {args.work_hours[0]:02d}h-{args.work_hours[1]:02d}h)")
    print("=" * 72)
    print(f"Off-hours USB connections: {len(events):,} | inside the user's own session: {len(strong):,}")
    print(f"Users with strong signals: {len(per_user)}")
    print()
    print(f"{'user':<10} {'strong_events':>13}  first event")
    print("-" * 72)
    first = {}
    for e in strong:
        first.setdefault(e.user, e)
    for user, n in per_user.head(args.top).items():
        e = first[user]
        print(f"{user:<10} {n:>13}  {e.usb_ts:%Y-%m-%d %H:%M} on {e.pc} "
              f"(session {e.session_start:%H:%M}-{e.session_end:%H:%M})")


if __name__ == "__main__":
    main()
