"""Analysis 4: file copies vs. peer-group baseline (ATT&CK T1052).

Compares each user's mean daily copy volume against the peer-group baseline
(median of the per-user means for the same LDAP role). Flags users who exceed
the role baseline by a factor. The deviation from peers, not the absolute value,
is what exposes the outlier. Uses the full file.csv.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

import pandas as pd

from insider_threat import loaders as _loaders
from insider_threat.baseline import individual_baseline, peer_group_baseline

__all__ = ["CopyFlag", "run", "main"]


@dataclass(frozen=True)
class CopyFlag:
    user: str
    role: str
    mean_copies_per_day: float
    peer_group_baseline: float
    factor: float


def run(sources: dict[str, pd.DataFrame], *, min_factor: float = 3.0) -> list[CopyFlag]:
    file_df = sources["file"]
    ldap_df = sources["ldap"]
    individual = individual_baseline(file_df)
    peer = peer_group_baseline(file_df, ldap_df)
    role_by_user = ldap_df.drop_duplicates("user_id").set_index("user_id")["role"].to_dict()
    flags: list[CopyFlag] = []
    for user, mean in individual.items():
        role = role_by_user.get(user)
        if role is None or role not in peer.index:
            continue
        base = float(peer.loc[role])
        if base > 0 and float(mean) > base * min_factor:
            flags.append(CopyFlag(str(user), str(role), float(mean), base, float(mean) / base))
    flags.sort(key=lambda f: (-f.factor, -f.mean_copies_per_day, f.user))
    return flags


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m analyses.a04_file_copy_baseline",
                                description="Analysis 4 (T1052): file copies vs. peer-group baseline.")
    p.add_argument("--factor", type=float, default=3.0,
                   help="Minimum factor above the role baseline to flag (default 3x).")
    p.add_argument("--top", type=int, default=20)
    args = p.parse_args(argv)

    sources = _loaders.load_sources()
    flags = run(sources, min_factor=args.factor)
    copiers = sources["file"]["user"].nunique()

    print("Analysis 4: file copies vs. peer-group baseline (T1052)")
    print("=" * 72)
    print(f"Users with file copies: {copiers} | above {args.factor:g}x their role baseline: {len(flags)}")
    print(f"{'user':<10} {'role':<24} {'copies/day':>10} {'role_base':>10} {'factor':>7}")
    print("-" * 72)
    for f in flags[: args.top]:
        print(f"{f.user:<10} {f.role:<24} {f.mean_copies_per_day:>10.1f} "
              f"{f.peer_group_baseline:>10.1f} {f.factor:>6.1f}x")


if __name__ == "__main__":
    main()
