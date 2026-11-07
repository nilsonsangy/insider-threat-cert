"""Analysis 5: signal correlation and risk-score ranking.

Sums, per user, an additive score over the signals present in the full dataset
(off-hours logon, off-hours USB inside the user's own session, copies above the
role baseline, and suspicious browsing from the full HTTP log), producing a
ranking of the users to investigate first. See ``insider_threat.score`` for the
weights.
"""

from __future__ import annotations

import argparse
from collections import Counter

from analyses import a01_web_browsing
from insider_threat import loaders as _loaders
from insider_threat.score import SuspectScore, score_by_user

__all__ = ["run", "main"]


def run(sources, *, web_users=None, work_hours=(7, 19), copy_factor=3.0) -> list[SuspectScore]:
    return score_by_user(sources, web_users=web_users, work_hours=work_hours,
                         copy_factor=copy_factor)


def load_inputs(*, verbose: bool = True):
    """Load the full sources plus the per-category web users (from the full HTTP log)."""
    sources = _loaders.load_sources()
    web_users = a01_web_browsing.web_users_by_category(
        a01_web_browsing.web_hits(verbose=verbose))
    return sources, web_users


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m analyses.a05_correlation",
                                description="Analysis 5: correlation and risk score.")
    p.add_argument("--top", type=int, default=25)
    args = p.parse_args(argv)

    sources, web_users = load_inputs()
    ranking = run(sources, web_users=web_users)
    total_users = sources["ldap"]["user_id"].nunique()

    print("Analysis 5: signal correlation (risk score ranking)")
    print("=" * 72)
    print(f"Users in LDAP: {total_users} | users with score > 0: {len(ranking)}")
    dist = Counter(s.score for s in ranking)
    print("Score distribution: " + ", ".join(f"{k}:{dist[k]}" for k in sorted(dist, reverse=True)))
    print()
    for i, s in enumerate(ranking[: args.top], 1):
        signals = ", ".join(f"{name}=+{w}" for name, w in sorted(s.signals.items()))
        print(f"{i:>3}. {s.user:<10} score={s.score:<2} [{signals}]")


if __name__ == "__main__":
    main()
