#!/usr/bin/env python3
"""Ingest the CERT r4.2 sources into OpenSearch.

By default the entire dataset is ingested: the five event indices (cert-logon,
cert-device, cert-file, cert-email, cert-http) and the derived indices
cert-copy-daily and cert-risk. The work is done by ``insider_threat.opensearch``;
this script only reads the options.

Configuration is read from the process environment, then from the ``.env``
file at the project root.

Usage:
    uv run python scripts/ingest_opensearch.py
    uv run python scripts/ingest_opensearch.py --only http --resume
"""

from __future__ import annotations

import argparse
import sys
import urllib.error

from insider_threat import env as _env
from insider_threat import loaders as _loaders
from insider_threat.opensearch.bulk import normalize_host, request
from insider_threat.opensearch.ingest import DERIVED_HANDLERS, build_context, ingest_source
from insider_threat.opensearch.mappings import DERIVED, SOURCES, index_name

_env.load_env()

_DEFAULT_HOST = "localhost:9200"
_DOWNLOAD_HINT = "uv run python scripts/download_cert.py --extract"


def _parse_only(value: str | None) -> list[str] | None:
    """Parse the comma-separated --only value; None means everything."""
    if not value:
        return None
    names = [n.strip() for n in value.split(",") if n.strip()]
    valid = list(SOURCES) + list(DERIVED)
    unknown = [n for n in names if n not in valid]
    if unknown:
        raise ValueError("unknown source(s): " + ", ".join(unknown) + ". Valid: " + ", ".join(valid))
    return names


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="scripts/ingest_opensearch.py",
                                description="Ingest the r4.2 sources into OpenSearch.")
    p.add_argument("--host", default=_env.get("OPENSEARCH_HOST", _DEFAULT_HOST),
                   help="OpenSearch host:port (default: OPENSEARCH_HOST or localhost:9200).")
    p.add_argument("--batch", type=int, default=10000, help="_bulk batch size.")
    p.add_argument("--only", default=None,
                   help="Comma-separated subset: logon, device, file, email, http, "
                        "copy-daily, risk (e.g. --only http,risk).")
    p.add_argument("--recreate", action="store_true",
                   help="Delete the selected indices before creating them again.")
    p.add_argument("--resume", action="store_true",
                   help="Continue an interrupted load from the last confirmed batch "
                        "(checkpoint in data/), never sending a stored row again.")
    p.add_argument("--start-row", type=int, default=None, metavar="N",
                   help="Start at data row N (0-based) of a single source, given with --only.")
    args = p.parse_args(argv)
    if (args.resume or args.start_row is not None) and args.recreate:
        print("ERROR: --resume/--start-row and --recreate cannot be used together.", file=sys.stderr)
        return 2
    try:
        only = _parse_only(args.only)
    except ValueError as e:
        print("ERROR: " + str(e), file=sys.stderr)
        return 2

    base = normalize_host(args.host)
    try:
        request("GET", base + "/")
    except urllib.error.URLError as e:
        print(f"ERROR: could not connect to OpenSearch at {base}: {getattr(e, 'reason', e)}. "
              "Start it with 'docker compose up -d'.", file=sys.stderr)
        return 1

    selected = only if only is not None else list(SOURCES) + list(DERIVED)
    sources = [n for n in selected if n in SOURCES]
    derived = [n for n in selected if n in DERIVED]
    if args.start_row is not None and len(sources) != 1:
        print("ERROR: --start-row needs exactly one source in --only (e.g. --only http).",
              file=sys.stderr)
        return 2

    data_dir = _loaders.dataset_dir()
    if not (data_dir / "logon.csv").is_file():
        print(f"ERROR: dataset not found at {data_dir}. Download it with: {_DOWNLOAD_HINT}",
              file=sys.stderr)
        return 1
    try:
        ctx = build_context()
    except (FileNotFoundError, ValueError) as e:
        print("ERROR: " + str(e), file=sys.stderr)
        return 1

    print("Connected to " + base + ". Ingesting...")
    grand_total = 0
    for name in sources:
        path = data_dir / (name + ".csv")
        if not path.is_file():
            print(f"  {name}: file missing ({path}), skipping.")
            continue
        print(f"  {index_name(name)}: indexing everything...", flush=True)
        n = ingest_source(base, name, path, ctx, batch=args.batch, recreate=args.recreate,
                          resume=args.resume, start_row=args.start_row)
        grand_total += n
        print(f"  {index_name(name)}: {n} docs.", flush=True)
    for name in derived:
        grand_total += DERIVED_HANDLERS[name](base, batch=args.batch, recreate=args.recreate)

    print(f"Ingestion finished: {grand_total} docs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())