#!/usr/bin/env python3
"""Analysis 1: suspicious web browsing (ATT&CK T1567).

Counts, per user and category, visits to job sites, leak sites, personal cloud
storage and spyware vendors in the full r4.2 http.csv (28M requests). The scan
and its cache (``data/derived/web_hits.csv``) live in ``insider_threat.web``,
so analyses 5, 6 and 7 and the cert-risk index reuse the same counts.

Usage:
    uv run python scripts/a01_web_browsing.py [--refresh] [--top N]
"""

from __future__ import annotations

import argparse

from insider_threat import domains as _domains
from insider_threat.web import web_hits


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="scripts/a01_web_browsing.py",
                                description="Analysis 1 (T1567): suspicious web browsing.")
    p.add_argument("--refresh", action="store_true",
                   help="Rescan http.csv even if the cached result is fresh.")
    p.add_argument("--top", type=int, default=10, help="Users to display per category.")
    args = p.parse_args(argv)

    hits = web_hits(refresh=args.refresh, verbose=True)
    print("Analysis 1: suspicious web browsing (http.csv)")
    print("=" * 72)
    for category in _domains.CATEGORIES:
        g = hits[hits["category"] == category]
        print(f"\n[{category}] {g['user'].nunique()} users, {int(g['visits'].sum()):,} visits "
              f"({', '.join(_domains.CATEGORIES[category][:4])}...)")
        print(f"  {'user':<10} {'visits':>8}  first visit")
        for r in g.head(args.top).itertuples(index=False):
            print(f"  {r.user:<10} {r.visits:>8}  {r.first_visit:%Y-%m-%d %H:%M}")


if __name__ == "__main__":
    main()