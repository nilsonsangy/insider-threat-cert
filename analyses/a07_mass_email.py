"""Analysis 7: mass email and USB candidates on the sender's machine.

Selects emails whose recipient count (``to`` + ``cc`` + ``bcc``) reaches a
threshold and, for each one, lists the USB connections made by a different user
on the same machine in the hours before the email was sent. Each candidate is
cross-checked against the users that visited spyware sites in the full
``http.csv`` (the same web signal used by analysis 5).

The risk score of analysis 5 and the numbers of analysis 6 are not affected.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

import pandas as pd

from analyses import a01_web_browsing
from insider_threat import loaders as _loaders
from insider_threat.mass_email import MASS_EMAIL_MIN_RECIPIENTS, recipient_count

__all__ = ["UsbCandidate", "MassEmail", "run", "main"]


@dataclass(frozen=True)
class UsbCandidate:
    user: str
    pc: str
    connect_ts: pd.Timestamp
    hours_before: float
    spyware_visitor: bool


@dataclass(frozen=True)
class MassEmail:
    date: pd.Timestamp
    user: str
    pc: str
    recipients: int
    size: int
    attachments: int
    candidates: tuple[UsbCandidate, ...]


def _to_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def run(sources: dict[str, pd.DataFrame], *, web_users: dict[str, set[str]] | None = None,
        min_recipients: int = MASS_EMAIL_MIN_RECIPIENTS,
        window_hours: float = 48) -> list[MassEmail]:
    email = sources["email"]
    device = sources["device"]
    spyware = set((web_users or {}).get("spyware", ()))

    counts = [recipient_count(t, c, b)
              for t, c, b in zip(email["to"], email["cc"], email["bcc"])]
    mass = email.assign(recipients=pd.Series(counts, index=email.index))
    mass = mass[mass["recipients"] >= min_recipients]

    connects = device[device["activity"].str.strip().str.lower() == "connect"]
    by_pc = {pc: g for pc, g in connects.groupby("pc")}

    window = pd.Timedelta(hours=window_hours)
    emails: list[MassEmail] = []
    for row in mass.itertuples(index=False):
        candidates: list[UsbCandidate] = []
        g = by_pc.get(row.pc)
        if g is not None:
            delta = row.date - g["date"]
            near = g[(g["user"] != row.user) & (delta >= pd.Timedelta(0)) & (delta <= window)]
            for u, ts in zip(near["user"], near["date"]):
                candidates.append(UsbCandidate(
                    user=str(u), pc=str(row.pc), connect_ts=ts,
                    hours_before=(row.date - ts).total_seconds() / 3600.0,
                    spyware_visitor=str(u) in spyware))
        candidates.sort(key=lambda c: (c.hours_before, c.user))
        emails.append(MassEmail(
            date=row.date, user=str(row.user), pc=str(row.pc),
            recipients=int(row.recipients), size=_to_int(row.size),
            attachments=_to_int(row.attachments), candidates=tuple(candidates)))
    emails.sort(key=lambda m: (m.date, m.user))
    return emails


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m analyses.a07_mass_email",
                                description="Analysis 7: mass email and USB candidates.")
    p.add_argument("--min-recipients", type=int, default=MASS_EMAIL_MIN_RECIPIENTS,
                   help="Minimum recipients (to + cc + bcc) of a mass email "
                        f"(default {MASS_EMAIL_MIN_RECIPIENTS}).")
    p.add_argument("--window-hours", type=float, default=48,
                   help="Hours before the email searched for USB connections (default 48).")
    p.add_argument("--refresh", action="store_true",
                   help="Rescan http.csv even if the cached result is fresh.")
    args = p.parse_args(argv)

    sources = _loaders.load_sources()
    web_users = a01_web_browsing.web_users_by_category(
        a01_web_browsing.web_hits(refresh=args.refresh, verbose=True))
    emails = run(sources, web_users=web_users, min_recipients=args.min_recipients,
                 window_hours=args.window_hours)

    total = sum(len(m.candidates) for m in emails)
    print("Analysis 7: mass email and USB candidates")
    print("=" * 72)
    print(f"Mass emails (>= {args.min_recipients} recipients): {len(emails)} | "
          f"USB candidates within {args.window_hours:g} h: {total}")
    for m in emails:
        print()
        print(f"{m.date:%Y-%m-%d %H:%M:%S} {m.user:<10} {m.pc:<9} "
              f"recipients={m.recipients} size={m.size} attachments={m.attachments}")
        print(f"  {'candidate':<10} {'connect':<19} {'hours_before':>12} {'spyware':>8}")
        for c in m.candidates:
            print(f"  {c.user:<10} {c.connect_ts:%Y-%m-%d %H:%M:%S} "
                  f"{c.hours_before:>12.1f} {str(c.spyware_visitor):>8}")


if __name__ == "__main__":
    main()
