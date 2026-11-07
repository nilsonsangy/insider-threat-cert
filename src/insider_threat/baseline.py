"""insider_threat.baseline: file-copy activity baselines (CERT r4.2).

In r4.2, ``file.csv`` records file copies (``id,date,user,pc,filename,content``)
and has no column indicating removable media. USB exfiltration is inferred by
correlating a copy with an active USB connection (see
``analyses.a02_usb_exfiltration``). Here we handle copy volume itself: per day,
per user, and the per-role baseline (LDAP peer group).

All functions are pure and deterministic (no network I/O).
"""

from __future__ import annotations

import pandas as pd

__all__ = ["copies_per_day", "individual_baseline", "peer_group_baseline"]


def copies_per_day(file_df: pd.DataFrame) -> pd.DataFrame:
    """Count file copies per ``(user, day)``.

    Each row of ``file.csv`` is one copy. Returns columns ``user``, ``day``
    (date) and ``copies`` (int), sorted by user/day.
    """
    _require(file_df, ["date", "user"], source="file_df")
    date = pd.to_datetime(file_df["date"])
    base = pd.DataFrame({"user": file_df["user"].to_numpy(), "day": date.dt.date.to_numpy()})
    if base.empty:
        return pd.DataFrame({"user": pd.Series(dtype=object),
                             "day": pd.Series(dtype=object),
                             "copies": pd.Series(dtype="int64")})
    agg = base.groupby(["user", "day"], sort=True).size().reset_index(name="copies")
    agg["copies"] = agg["copies"].astype("int64")
    return agg.sort_values(["user", "day"]).reset_index(drop=True)


def individual_baseline(file_df: pd.DataFrame) -> pd.Series:
    """Mean daily copies per user (over the days on which a copy happened)."""
    per_day = copies_per_day(file_df)
    if per_day.empty:
        return pd.Series(dtype="float64", name="individual_baseline",
                         index=pd.Index([], name="user"))
    mean = per_day.groupby("user", sort=True)["copies"].mean()
    mean.name = "individual_baseline"
    mean.index.name = "user"
    return mean


def peer_group_baseline(file_df: pd.DataFrame, ldap_df: pd.DataFrame) -> pd.Series:
    """Copies/day baseline per LDAP ``role``, robust to outliers.

    Starts from the individual daily means and takes the median per role. The
    median is naturally robust to the few insiders who copy far more than their
    peers, giving a reference for what is normal for the role.
    """
    _require(ldap_df, ["user_id", "role"], source="ldap_df")
    individual = individual_baseline(file_df)
    if individual.empty:
        return pd.Series(dtype="float64", name="peer_group_baseline",
                         index=pd.Index([], name="role"))
    role_by_user = (ldap_df[["user_id", "role"]].drop_duplicates("user_id")
                    .set_index("user_id")["role"])
    means = individual.rename_axis("user").reset_index(name="mean")
    means["role"] = means["user"].map(role_by_user)
    means = means.dropna(subset=["role"])
    if means.empty:
        return pd.Series(dtype="float64", name="peer_group_baseline",
                         index=pd.Index([], name="role"))
    base = means.groupby("role", sort=True)["mean"].median()
    base.name = "peer_group_baseline"
    base.index.name = "role"
    return base


def _require(df: pd.DataFrame, cols: list[str], *, source: str) -> None:
    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise ValueError(f"{source}: missing column(s) {missing}; required {cols}.")
