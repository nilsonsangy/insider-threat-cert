"""insider_threat.loaders: loading the CERT Insider Threat Dataset (r4.2) sources.

Loads the full activity sources, LDAP data and the official answer key from
``data/`` (where the real dataset is downloaded and extracted by
``scripts/download_cert.py``). Expected layout after extraction:

    data/
      r4.2/
        logon.csv            id,date,user,pc,activity           (Logon|Logoff)
        device.csv           id,date,user,pc,activity           (Connect|Disconnect)
        file.csv             id,date,user,pc,filename,content
        http.csv             id,date,user,pc,url,content        (~14 GB)
        email.csv            id,date,user,pc,to,cc,bcc,from,size,attachments,content
        LDAP/
          YYYY-MM.csv        employee_name,user_id,email,role,...,supervisor
      answers/
        insiders.csv         dataset,scenario,details,user,start,end

Every function reads the complete files; there are no row limits or samples.
The free-text ``content`` column (synthetic document/e-mail/page bodies) is not
used by any analysis, so it is skipped at read time to keep memory low.
``http.csv`` is too large to hold in memory comfortably and is exposed as a
chunked iterator (:func:`iter_http`) that still covers every row.
"""

from __future__ import annotations

import os
from pathlib import Path

import pandas as pd

# r4.2 date format.
_DATE_FORMAT = "%m/%d/%Y %H:%M:%S"

# Target release (used to filter the answer key, which covers all releases).
RELEASE = "4.2"

# Columns read per source (r4.2 schema, without the unused `content` column).
COLUMNS: dict[str, tuple[str, ...]] = {
    "logon": ("id", "date", "user", "pc", "activity"),
    "device": ("id", "date", "user", "pc", "activity"),
    "file": ("id", "date", "user", "pc", "filename"),
    "http": ("id", "date", "user", "pc", "url"),
    "email": ("id", "date", "user", "pc", "to", "cc", "bcc", "from",
              "size", "attachments"),
}


def data_root(data_dir: str | Path | None = None) -> Path:
    """Data root. Default: <repo>/data (or the INSIDER_THREAT_DATA env var)."""
    if data_dir is not None:
        return Path(data_dir)
    env = os.environ.get("INSIDER_THREAT_DATA")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent.parent / "data"


def dataset_dir(data_dir: str | Path | None = None) -> Path:
    """Directory holding the activity CSVs (data/r4.2)."""
    d = data_root(data_dir) / f"r{RELEASE}"
    if not (d / "logon.csv").is_file():
        raise FileNotFoundError(
            f"Dataset not found at {d}. Download and extract it with: "
            f"python scripts/download_cert.py --extract"
        )
    return d


def _check_columns(name: str, path: Path, header: list[str]) -> None:
    missing = [c for c in COLUMNS[name] if c not in header]
    if missing:
        raise ValueError(
            f"Source '{name}' ({path.name}) is missing column(s): {', '.join(missing)}."
        )


def _parse_dates(name: str, df: pd.DataFrame) -> pd.DataFrame:
    parsed = pd.to_datetime(df["date"], format=_DATE_FORMAT, errors="coerce")
    bad = df["date"][parsed.isna()]
    if len(bad) > 0:
        raise ValueError(
            f"Source '{name}': 'date' does not match format {_DATE_FORMAT} "
            f"(e.g. {bad.iloc[0]!r})."
        )
    df["date"] = parsed
    return df


def load_source(name: str, data_dir: str | Path | None = None) -> pd.DataFrame:
    """Load one complete activity source (logon, device, file or email)."""
    if name == "http":
        raise ValueError("http.csv is too large to load at once; use iter_http().")
    path = dataset_dir(data_dir) / f"{name}.csv"
    if not path.is_file():
        raise FileNotFoundError(f"Source '{name}' is missing: {path}.")
    header = list(pd.read_csv(path, nrows=0).columns)
    _check_columns(name, path, header)
    df = pd.read_csv(path, dtype=str, keep_default_na=False,
                     usecols=list(COLUMNS[name]))
    return _parse_dates(name, df[list(COLUMNS[name])])


def load_ldap(data_dir: str | Path | None = None) -> pd.DataFrame:
    """Load LDAP (monthly folder) as a single per-user DataFrame.

    r4.2 ships one snapshot per month in ``LDAP/YYYY-MM.csv``. We consolidate all
    of them and keep the most recent record of each ``user_id`` (the role and
    department in effect when the user was last seen), which is enough to build
    the per-role peer group.
    """
    ldap_dir = dataset_dir(data_dir) / "LDAP"
    files = sorted(ldap_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No LDAP CSV files in {ldap_dir}.")
    parts: list[pd.DataFrame] = []
    for i, path in enumerate(files):
        d = pd.read_csv(path, dtype=str, keep_default_na=False)
        d["_month"] = i  # chronological order from the YYYY-MM file names
        parts.append(d)
    allrows = pd.concat(parts, ignore_index=True)
    for col in ("user_id", "role"):
        if col not in allrows.columns:
            raise ValueError(f"LDAP has no '{col}' column (columns: {list(allrows.columns)}).")
    allrows = allrows.sort_values("_month", kind="stable").drop_duplicates("user_id", keep="last")
    return allrows.drop(columns=["_month"]).reset_index(drop=True)


def load_answer_key(data_dir: str | Path | None = None) -> pd.DataFrame:
    """Load the official insider answer key filtered to release r4.2.

    Reads ``data/answers/insiders.csv`` (columns dataset,scenario,details,user,
    start,end) and returns only the rows of the target release.
    """
    path = data_root(data_dir) / "answers" / "insiders.csv"
    if not path.is_file():
        raise FileNotFoundError(
            f"Answer key missing: {path}. Download/extract it with "
            f"python scripts/download_cert.py --extract."
        )
    key = pd.read_csv(path, dtype=str, keep_default_na=False)
    if "dataset" not in key.columns or "user" not in key.columns:
        raise ValueError(f"insiders.csv has unexpected columns: {list(key.columns)}.")
    key = key[key["dataset"].str.strip() == RELEASE].reset_index(drop=True)
    key["user"] = key["user"].str.strip()
    return key


def load_sources(data_dir: str | Path | None = None) -> dict[str, pd.DataFrame]:
    """Load the complete logon, device, file, email, LDAP and answer key.

    ``http`` is not included (it is ~14 GB); use :func:`iter_http`.
    """
    sources = {name: load_source(name, data_dir)
               for name in ("logon", "device", "file", "email")}
    sources["ldap"] = load_ldap(data_dir)
    sources["answer_key"] = load_answer_key(data_dir)
    return sources


def iter_http(data_dir: str | Path | None = None, *, chunksize: int = 1_000_000):
    """Iterate over every row of ``http.csv`` in chunks, with 'date' parsed.

    Covers the whole file; chunking only bounds memory use.
    """
    path = dataset_dir(data_dir) / "http.csv"
    if not path.is_file():
        raise FileNotFoundError(f"http.csv is missing: {path}.")
    header = list(pd.read_csv(path, nrows=0).columns)
    _check_columns("http", path, header)
    for chunk in pd.read_csv(path, dtype=str, keep_default_na=False,
                             usecols=list(COLUMNS["http"]), chunksize=chunksize):
        yield _parse_dates("http", chunk[list(COLUMNS["http"])])
