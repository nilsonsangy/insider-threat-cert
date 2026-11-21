"""insider_threat.opensearch.ingest: streaming each source and the derived indices.

The activity sources and http.csv are read in streaming mode and indexed batch
by batch through the _bulk API, so the large files (http is about 14 GB) are
never loaded into memory. Every row passes through
``insider_threat.enrich.enrich_row`` before indexing.
"""

from __future__ import annotations

import csv
import functools
import json
import sys

from insider_threat import loaders as _loaders
from insider_threat.domains import category_of_host
from insider_threat.enrich import EnrichContext, enrich_row
from insider_threat.opensearch import derived as _derived
from insider_threat.opensearch.bulk import bulk_documents, create_index, finalize_index, send_bulk
from insider_threat.opensearch.mappings import DISCARD, SOURCES, index_name, iso_date
from insider_threat.opensearch.resume import resume_point, rows_from, write_checkpoint

__all__ = ["build_context", "ingest_source", "ingest_copy_daily", "ingest_risk", "DERIVED_HANDLERS"]


def _log(message: str) -> None:
    print(message, flush=True)


def build_context(data_dir=None) -> EnrichContext:
    """Enrichment context: LDAP roles (most recent snapshot) and host cache."""
    host_category = functools.lru_cache(maxsize=None)(category_of_host)
    return EnrichContext(roles=_derived.roles_from_ldap(data_dir), host_category=host_category)


def ingest_source(base, name, path, ctx, *, batch=10000, recreate=False,
                  resume=False, start_row=None) -> int:
    """Index one source CSV into ``cert-<name>``. Returns the documents created.

    With ``resume`` or ``start_row`` the load jumps straight to the first row
    that is not stored and sends the rest as ``create``: no row is sent twice.
    """
    index = index_name(name)
    create_index(base, name, recreate=recreate)
    keep = [c for c in SOURCES[name] if c not in DISCARD]

    offset, already = (0, 0)
    resuming = resume or start_row is not None
    if resuming:
        offset, already = resume_point(base, index, name, path, start_row, log=_log)
    op = "create" if resuming else "index"

    total = 0
    skipped = 0
    existing = 0
    buffer: list[str] = []
    last_end = offset
    for row, end in rows_from(path, offset):
        last_end = end
        doc = {c: row.get(c, "") for c in keep}
        iso = iso_date(doc.get("date", ""))
        if iso is None:
            # A row without a valid date cannot be placed on the time axis.
            skipped += 1
            continue
        doc["date"] = iso
        doc = enrich_row(index, doc, ctx)
        # Deterministic _id = the unique CERT row id.
        doc_id = row.get("id") or None
        action = {"_index": index}
        if doc_id:
            action["_id"] = doc_id
        buffer.append(json.dumps({op: action}) + "\n")
        buffer.append(json.dumps(doc, ensure_ascii=False) + "\n")
        total += 1
        if len(buffer) >= batch * 2:
            existing += send_bulk(base, index, buffer)
            buffer.clear()
            write_checkpoint(name, path, last_end, already + total)
            if (already + total) % 100000 == 0:
                _log(f"    {name}: {already + total} docs...")
    if buffer:
        existing += send_bulk(base, index, buffer)
        write_checkpoint(name, path, last_end, already + total)
    finalize_index(base, index)
    if skipped:
        print(f"    {name}: {skipped} rows skipped (invalid date).", file=sys.stderr)
    if existing:
        _log(f"    {name}: {existing} rows were already stored and were left untouched.")
    return total - existing


def ingest_copy_daily(base, *, batch=10000, recreate=False) -> int:
    index = index_name("copy-daily")
    path = _loaders.dataset_dir() / "file.csv"
    try:
        documents = _derived.copy_daily_documents(path, _derived.roles_from_ldap())
    except (OSError, ValueError, csv.Error) as e:
        print(f"  {index}: cancelled, could not read {path}: {e}", file=sys.stderr)
        return 0
    _log(f"  {index}: indexing {len(documents)} user-days...")
    n = bulk_documents(base, "copy-daily", documents, batch=batch, recreate=recreate)
    _log(f"  {index}: {n} docs.")
    return n


def ingest_risk(base, *, batch=10000, recreate=False) -> int:
    index = index_name("risk")
    try:
        documents = _derived.risk_documents()
    except (OSError, ValueError, KeyError) as e:
        print(f"  {index}: cancelled, could not read the dataset: {e}", file=sys.stderr)
        return 0
    _log(f"  {index}: indexing {len(documents)} users...")
    n = bulk_documents(base, "risk", documents, batch=batch, recreate=recreate)
    _log(f"  {index}: {n} docs.")
    return n


DERIVED_HANDLERS = {"copy-daily": ingest_copy_daily, "risk": ingest_risk}