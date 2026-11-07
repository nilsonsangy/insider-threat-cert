"""Analysis 1: suspicious web browsing (ATT&CK T1567).

Streams every row of the r4.2 http.csv (28M requests) and counts, per user and
category, visits to job sites, leak sites, personal cloud storage and spyware
vendors (see ``insider_threat.domains``).

The per-user counts are cached in ``data/derived/web_hits.csv`` (gitignored,
derived only from the real http.csv) so analyses 5 and 6 can reuse them. The
cache is rebuilt automatically when http.csv is newer, or with ``--refresh``.
"""

from __future__ import annotations

import argparse
import time

import pandas as pd

from insider_threat import domains as _domains
from insider_threat import loaders as _loaders

__all__ = ["web_hits", "web_users_by_category", "main"]

_COLUMNS = ["user", "category", "visits", "first_visit"]


def _cache_path(data_dir=None):
    return _loaders.data_root(data_dir) / "derived" / "web_hits.csv"


def compute_web_hits(data_dir=None, *, verbose: bool = False) -> pd.DataFrame:
    """Scan the full http.csv and return visits per (user, category)."""
    parts: list[pd.DataFrame] = []
    rows = 0
    t0 = time.time()
    for chunk in _loaders.iter_http(data_dir):
        rows += len(chunk)
        cat = _domains.classify_series(chunk["url"])
        hits = chunk.loc[cat.notna(), ["user", "date"]].assign(category=cat[cat.notna()])
        if not hits.empty:
            parts.append(hits.groupby(["user", "category"])
                         .agg(visits=("date", "size"), first_visit=("date", "min"))
                         .reset_index())
        if verbose:
            print(f"\r  scanned {rows:,} HTTP rows ({time.time() - t0:.0f}s)", end="", flush=True)
    if verbose:
        print()
    if not parts:
        return pd.DataFrame(columns=_COLUMNS)
    allhits = pd.concat(parts, ignore_index=True)
    out = (allhits.groupby(["user", "category"])
           .agg(visits=("visits", "sum"), first_visit=("first_visit", "min"))
           .reset_index())
    out.attrs["http_rows"] = rows
    return out[_COLUMNS].sort_values(["category", "visits", "user"],
                                     ascending=[True, False, True]).reset_index(drop=True)


def web_hits(data_dir=None, *, refresh: bool = False, verbose: bool = False) -> pd.DataFrame:
    """Return the per-(user, category) web hits, using the cache when it is fresh."""
    cache = _cache_path(data_dir)
    http_csv = _loaders.dataset_dir(data_dir) / "http.csv"
    if (not refresh and cache.is_file()
            and cache.stat().st_mtime >= http_csv.stat().st_mtime):
        df = pd.read_csv(cache, dtype={"user": str, "category": str})
        df["first_visit"] = pd.to_datetime(df["first_visit"])
        return df
    df = compute_web_hits(data_dir, verbose=verbose)
    cache.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(cache, index=False)
    return df


def web_users_by_category(hits: pd.DataFrame) -> dict[str, set[str]]:
    """Map each category to the set of users that visited it."""
    return {c: set(g["user"]) for c, g in hits.groupby("category")}


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m analyses.a01_web_browsing",
                                description="Analysis 1 (T1567): suspicious web browsing.")
    p.add_argument("--refresh", action="store_true",
                   help="Rescan http.csv even if the cached result is fresh.")
    p.add_argument("--top", type=int, default=10, help="Users to display per category.")
    args = p.parse_args(argv)

    hits = web_hits(refresh=args.refresh, verbose=True)
    print("Analysis 1: suspicious web browsing (full http.csv)")
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
