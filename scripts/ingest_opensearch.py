#!/usr/bin/env python3
"""Ingest the CERT r4.2 sources into OpenSearch.

By default the entire dataset is ingested. The activity sources (logon, device,
file, email) and http.csv are read in streaming mode and indexed batch by batch
through the _bulk API, so the large files (http is about 14 GB) are never
loaded into memory.

Every row passes through ``insider_threat.enrich.enrich_row`` before indexing,
which adds the derived fields (``off_hours``, ``role``, ``recipients``,
``domain``, ``category`` and the typed e-mail fields).

Indices: cert-logon, cert-device, cert-file, cert-email, cert-http, plus the
derived indices cert-copy-daily and cert-risk.

Configuration is read from the process environment, then from the ``.env``
file at the project root. Only the standard library is used for HTTP transport.
"""

from __future__ import annotations

import argparse
import csv
import functools
import json
import sys
from datetime import datetime
import urllib.error
import urllib.request
from pathlib import Path

from insider_threat import env as _env
from insider_threat import loaders as _loaders
from insider_threat.domains import category_of_host
from insider_threat.enrich import EnrichContext, enrich_row

_env.load_env()

_INDEX_PREFIX = "cert-"
_DEFAULT_HOST = "localhost:9200"
_TIMEOUT = 120
_DOWNLOAD_HINT = "uv run python scripts/download_cert.py --extract"

# Sources to ingest and their columns (r4.2 schema).
SOURCES = {
    "logon": ["id", "date", "user", "pc", "activity"],
    "device": ["id", "date", "user", "pc", "activity"],
    "file": ["id", "date", "user", "pc", "filename", "content"],
    "email": ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments", "content"],
    "http": ["id", "date", "user", "pc", "url", "content"],
}
# Derived indices built after the sources (see _DERIVED_HANDLERS).
DERIVED = ("copy-daily", "risk")
# Long-text columns that are not indexed (saves space and time).
DISCARD = {"content"}

_KEYWORD = {"type": "keyword"}
_DATE = {"type": "date"}
_INTEGER = {"type": "integer"}
_BOOLEAN = {"type": "boolean"}

_EVENT_BASE = {"id": _KEYWORD, "user": _KEYWORD, "pc": _KEYWORD, "role": _KEYWORD,
               "date": _DATE, "off_hours": _BOOLEAN}

# Explicit mappings. Fields with the same name have the same type in every index.
MAPPINGS: dict[str, dict[str, dict]] = {
    "logon": {**_EVENT_BASE, "activity": _KEYWORD},
    "device": {**_EVENT_BASE, "activity": _KEYWORD},
    "file": {**_EVENT_BASE, "filename": _KEYWORD},
    "email": {**_EVENT_BASE, "from": _KEYWORD,
              "to": _KEYWORD, "cc": _KEYWORD, "bcc": _KEYWORD,
              "size": _INTEGER, "attachments": _INTEGER, "recipients": _INTEGER},
    # The URL stays in _source only: indexing it would multiply the index size.
    "http": {**_EVENT_BASE, "domain": _KEYWORD, "category": _KEYWORD,
             "url": {"type": "keyword", "index": False, "doc_values": False}},
    "copy-daily": {"user": _KEYWORD, "role": _KEYWORD, "date": _DATE, "copies": _INTEGER},
    "risk": {"user": _KEYWORD, "role": _KEYWORD,
             "off_hours_logon": _BOOLEAN, "off_hours_usb": _BOOLEAN,
             "copy_above_baseline": _BOOLEAN, "job_or_cloud_web": _BOOLEAN,
             "leak_or_spyware_web": _BOOLEAN, "score": _INTEGER,
             "in_answer_key": _BOOLEAN, "scenario": _KEYWORD},
}


def _iso_date(value: str) -> str | None:
    """Convert the CERT 'MM/DD/YYYY HH:MM:SS' date to ISO-8601; None if empty/invalid."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.strptime(value, "%m/%d/%Y %H:%M:%S").isoformat()
    except ValueError:
        return None


def _normalize_host(h: str) -> str:
    h = h.strip()
    if not h.startswith(("http://", "https://")):
        h = "http://" + h
    return h.rstrip("/")


def _request(method, url, *, data=None, content_type=None):
    r = urllib.request.Request(url, data=data, method=method)
    if content_type:
        r.add_header("Content-Type", content_type)
    with urllib.request.urlopen(r, timeout=_TIMEOUT) as resp:
        return resp.status, resp.read()


def _delete_index(base, index):
    try:
        _request("DELETE", base + "/" + index)
    except urllib.error.HTTPError as e:
        if e.code != 404:  # 404 = index does not exist
            raise


def _create_index(base, name, *, recreate=False):
    index = _INDEX_PREFIX + name
    if recreate:
        _delete_index(base, index)
    body = json.dumps({
        "settings": {"number_of_replicas": 0, "refresh_interval": "-1"},
        "mappings": {"properties": MAPPINGS[name]},
    }).encode("utf-8")
    try:
        _request("PUT", base + "/" + index, data=body, content_type="application/json")
    except urllib.error.HTTPError as e:
        if e.code != 400:  # 400 = index already exists
            raise


def _finalize_index(base, index):
    # Turn refresh back on and force a refresh so documents become searchable.
    body = json.dumps({"index": {"refresh_interval": "1s"}}).encode("utf-8")
    try:
        _request("PUT", base + "/" + index + "/_settings", data=body, content_type="application/json")
        _request("POST", base + "/" + index + "/_refresh")
    except urllib.error.URLError:
        pass


def _send_bulk(base, index, ndjson_lines):
    """Send one _bulk request. Returns the number of documents that already existed.

    A ``create`` action on an existing ``_id`` returns a 409 conflict: the stored
    document is kept untouched and the conflict is counted, not raised.
    """
    body = ("".join(ndjson_lines)).encode("utf-8")
    _status, resp = _request("POST", base + "/_bulk", data=body,
                             content_type="application/x-ndjson")
    payload = json.loads(resp)
    existing = 0
    if payload.get("errors"):
        for item in payload.get("items", []):
            action = next(iter(item.values()))
            error = action.get("error")
            if not error:
                continue
            if action.get("status") == 409:
                existing += 1
                continue
            raise RuntimeError(f"OpenSearch rejected a document in '{index}': {error}")
    return existing


def _stored_count(base, index) -> int:
    """Refresh ``index`` and return how many documents it holds (0 if it does not exist)."""
    try:
        _request("POST", base + "/" + index + "/_refresh")
        _status, resp = _request("GET", base + "/" + index + "/_count")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return 0
        raise
    return int(json.loads(resp).get("count", 0))


def _build_context(data_dir: Path | None = None) -> EnrichContext:
    """Build the enrichment context: LDAP roles (most recent snapshot) and host cache."""
    ldap = _loaders.load_ldap(data_dir)
    roles = dict(zip(ldap["user_id"], ldap["role"]))
    host_category = functools.lru_cache(maxsize=None)(category_of_host)
    return EnrichContext(roles=roles, host_category=host_category)


_CHUNK = 64 * 1024 * 1024


def _checkpoint_path(name) -> Path:
    """Checkpoint of the last confirmed batch, kept in the (unversioned) data folder."""
    return _loaders.data_root() / f".ingest-{name}.json"


def _read_checkpoint(name, path) -> dict | None:
    cp = _checkpoint_path(name)
    if not cp.is_file():
        return None
    try:
        data = json.loads(cp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    st = path.stat()
    if data.get("size") != st.st_size or data.get("mtime") != int(st.st_mtime):
        return None  # the CSV changed: the stored offset is no longer valid
    return data


def _write_checkpoint(name, path, offset, rows) -> None:
    st = path.stat()
    data = {"source": name, "offset": offset, "rows": rows,
            "size": st.st_size, "mtime": int(st.st_mtime)}
    _checkpoint_path(name).write_text(json.dumps(data), encoding="utf-8")


def _offset_of_row(path, row) -> int:
    """Byte offset where data row ``row`` (0-based, header excluded) starts.

    Counts newlines in large binary blocks, without parsing the CSV, so it costs
    a few seconds even for the 14 GB http.csv. It assumes one physical line per
    row; the caller confirms the result against the stored documents.
    """
    target = row + 1  # the header is line 0
    seen = 0
    pos = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(_CHUNK)
            if not block:
                break
            n = block.count(b"\n")
            if seen + n >= target:
                start = 0
                for _ in range(target - seen):
                    start = block.index(b"\n", start) + 1
                return pos + start
            seen += n
            pos += len(block)
    return pos


def _rows_from(path, offset):
    """Yield ``(row, end_offset)`` from ``offset`` on, reading the file in binary.

    A line with an unbalanced quote is joined with the next ones, so a quoted
    field with an embedded newline stays in one row.
    """
    with open(path, "rb") as fh:
        header = next(csv.reader([fh.readline().decode("utf-8")]))
        if offset:
            fh.seek(offset)
        pending = b""
        for line in fh:
            pending += line
            if pending.count(b'"') % 2:
                continue
            text = pending.decode("utf-8").rstrip("\r\n")
            pending = b""
            values = next(csv.reader([text]), [])
            yield dict(zip(header, values)), fh.tell()


def _first_id_at(path, offset) -> str | None:
    for row, _end in _rows_from(path, offset):
        return row.get("id") or None
    return None


def _stored(base, index, doc_id) -> bool:
    try:
        _request("GET", base + "/" + index + "/_doc/" + urllib.request.quote(doc_id, safe=""))
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise


def _resume_point(base, index, name, path, start_row):
    """Return ``(offset, rows_before)`` for a resumed load, or raise if unsafe.

    Uses the checkpoint when it exists; otherwise ``start_row`` or, by default,
    the number of stored documents. The row right before the start must be
    stored and the row at the start must not be.
    """
    cp = _read_checkpoint(name, path) if start_row is None else None
    if cp:
        offset, rows = cp["offset"], cp["rows"]
        print(f"    {name}: checkpoint found, {rows} rows confirmed.", flush=True)
        prev_id = None
    else:
        rows = start_row if start_row is not None else _stored_count(base, index)
        if rows == 0:
            return 0, 0
        # One newline count: the row before the start, then the start right after it.
        before = _offset_of_row(path, rows - 1)
        prev_id, offset = None, before
        for row, end in _rows_from(path, before):
            prev_id, offset = row.get("id") or None, end
            break
        print(f"    {name}: starting at row {rows} (byte {offset}).", flush=True)
    next_id = _first_id_at(path, offset)
    if prev_id is not None and not _stored(base, index, prev_id):
        raise RuntimeError(f"row {rows - 1} ({prev_id}) is not stored: the start point is wrong.")
    if next_id is not None and _stored(base, index, next_id):
        raise RuntimeError(f"row {rows} ({next_id}) is already stored: the start point is wrong.")
    return offset, rows


def _index_streaming(base, name, columns, path, ctx, *, batch=10000, recreate=False,
                     resume=False, start_row=None):
    index = _INDEX_PREFIX + name
    _create_index(base, name, recreate=recreate)
    keep = [c for c in columns if c not in DISCARD]

    # Resume: jump straight to the first row that is not stored (byte offset from
    # the checkpoint or from a fast newline count) and send the rest as
    # ``create``, which never overwrites a stored document. No row is sent twice.
    offset, already = (0, 0)
    if resume or start_row is not None:
        offset, already = _resume_point(base, index, name, path, start_row)
    op = "create" if (resume or start_row is not None) else "index"

    total = 0
    skipped = 0
    existing = 0
    buffer: list[str] = []
    last_end = offset
    for row, end in _rows_from(path, offset):
        last_end = end
        doc = {c: row.get(c, "") for c in keep}
        iso = _iso_date(doc.get("date", ""))
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
            existing += _send_bulk(base, index, buffer)
            buffer.clear()
            _write_checkpoint(name, path, last_end, already + total)
            if (already + total) % 100000 == 0:
                print(f"    {name}: {already + total} docs...", flush=True)
    if buffer:
        existing += _send_bulk(base, index, buffer)
        _write_checkpoint(name, path, last_end, already + total)
    _finalize_index(base, index)
    if skipped:
        print(f"    {name}: {skipped} rows skipped (invalid date).", file=sys.stderr)
    if existing:
        print(f"    {name}: {existing} rows were already stored and were left untouched.")
    return total - existing

# Hooks for the derived indices. Each receives (base, args) and returns the
# number of documents indexed.
def _bulk_documents(base, name, documents, *, batch, recreate):
    """Index ``(id, doc)`` pairs into ``cert-<name>`` and finalize the index."""
    index = _INDEX_PREFIX + name
    _create_index(base, name, recreate=recreate)
    buffer: list[str] = []
    total = 0
    for doc_id, doc in documents:
        buffer.append(json.dumps({"index": {"_index": index, "_id": doc_id}}) + "\n")
        buffer.append(json.dumps(doc, ensure_ascii=False) + "\n")
        total += 1
        if len(buffer) >= batch * 2:
            _send_bulk(base, index, buffer)
            buffer.clear()
    if buffer:
        _send_bulk(base, index, buffer)
    _finalize_index(base, index)
    return total


def _read_copy_daily(path, roles) -> list[tuple[str, dict]]:
    """Accumulate file copies per (user, day) while reading file.csv."""
    counts: dict[tuple[str, str], int] = {}
    with open(path, "r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            iso = _iso_date(row.get("date", ""))
            user = (row.get("user") or "").strip()
            if iso is None or not user:
                continue
            key = (user, iso[:10])
            counts[key] = counts.get(key, 0) + 1
    documents = []
    for (user, day), copies in sorted(counts.items()):
        doc = {"user": user, "date": day, "copies": copies}
        role = roles.get(user)
        if role:
            doc["role"] = role
        documents.append((user + "|" + day, doc))
    return documents


def _ingest_copy_daily(base, args) -> int:
    index = _INDEX_PREFIX + "copy-daily"
    path = _loaders.data_root() / f"r{_loaders.RELEASE}" / "file.csv"
    try:
        ldap = _loaders.load_ldap()
        roles = dict(zip(ldap["user_id"], ldap["role"]))
        documents = _read_copy_daily(path, roles)
    except (OSError, ValueError, csv.Error) as e:
        print("  " + index + ": cancelled, could not read " + str(path) + ": " + str(e),
              file=sys.stderr)
        return 0
    print("  " + index + ": indexing " + str(len(documents)) + " user-days...")
    n = _bulk_documents(base, "copy-daily", documents,
                        batch=args.batch, recreate=args.recreate)
    print("  " + index + ": " + str(n) + " docs.")
    return n


def _risk_documents() -> list[tuple[str, dict]]:
    """Build one risk document per LDAP user from the five signals and the score."""
    # The analyses package lives at the project root, next to scripts/.
    root = str(Path(__file__).resolve().parent.parent)
    if root not in sys.path:
        sys.path.insert(0, root)
    from analyses import a01_web_browsing
    from insider_threat import score as _score

    sources = _loaders.load_sources()
    web_users = a01_web_browsing.web_users_by_category(a01_web_browsing.web_hits())
    presence = _score.signal_users(sources, web_users=web_users)

    ldap = sources["ldap"]
    roles = dict(zip(ldap["user_id"], ldap["role"]))
    key = sources["answer_key"]
    scenarios: dict[str, str] = {}
    for user, scenario in zip(key["user"], key["scenario"]):
        scenarios.setdefault(user, str(scenario).strip())

    documents = []
    for user in sorted(roles):
        doc: dict = {"user": user}
        if roles[user]:
            doc["role"] = roles[user]
        total = 0
        for signal, weight in _score.WEIGHTS.items():
            present = user in presence[signal]
            doc[signal] = present
            total += weight if present else 0
        doc["score"] = total
        # Evaluation only: not a detection input.
        doc["in_answer_key"] = user in scenarios
        if user in scenarios and scenarios[user]:
            doc["scenario"] = scenarios[user]
        documents.append((user, doc))
    return documents


def _ingest_risk(base, args) -> int:
    index = _INDEX_PREFIX + "risk"
    try:
        documents = _risk_documents()
    except (OSError, ValueError, KeyError) as e:
        print("  " + index + ": cancelled, could not read the dataset: " + str(e),
              file=sys.stderr)
        return 0
    print("  " + index + ": indexing " + str(len(documents)) + " users...")
    n = _bulk_documents(base, "risk", documents,
                        batch=args.batch, recreate=args.recreate)
    print("  " + index + ": " + str(n) + " docs.")
    return n


_DERIVED_HANDLERS = {"copy-daily": _ingest_copy_daily, "risk": _ingest_risk}


def _parse_only(value: str | None) -> list[str] | None:
    """Parse the comma-separated --only value; None means everything."""
    if not value:
        return None
    names = [n.strip() for n in value.split(",") if n.strip()]
    valid = list(SOURCES) + list(DERIVED)
    unknown = [n for n in names if n not in valid]
    if unknown:
        raise ValueError("unknown source(s): " + ", ".join(unknown)
                         + ". Valid: " + ", ".join(valid))
    return names


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ingest_opensearch.py",
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

    base = _normalize_host(args.host)
    try:
        _request("GET", base + "/")
    except urllib.error.URLError as e:
        print("ERROR: could not connect to OpenSearch at " + base + ": "
              + str(getattr(e, "reason", e)) + ". Start it with "
              + "'docker compose up -d'.", file=sys.stderr)
        return 1

    selected = only if only is not None else list(SOURCES) + list(DERIVED)
    sources = [n for n in selected if n in SOURCES]
    derived = [n for n in selected if n in DERIVED]
    if args.start_row is not None and len(sources) != 1:
        print("ERROR: --start-row needs exactly one source in --only (e.g. --only http).",
              file=sys.stderr)
        return 2

    data_dir = _loaders.data_root() / f"r{_loaders.RELEASE}"
    if not (data_dir / "logon.csv").is_file():
        print("ERROR: dataset not found at " + str(data_dir)
              + ". Download it with: " + _DOWNLOAD_HINT, file=sys.stderr)
        return 1

    try:
        ctx = _build_context()
    except (FileNotFoundError, ValueError) as e:
        print("ERROR: " + str(e), file=sys.stderr)
        return 1

    print("Connected to " + base + ". Ingesting...")
    grand_total = 0
    for name in sources:
        path = data_dir / (name + ".csv")
        if not path.is_file():
            print("  " + name + ": file missing (" + str(path) + "), skipping.")
            continue
        print("  " + _INDEX_PREFIX + name + ": indexing everything...")
        n = _index_streaming(base, name, SOURCES[name], path, ctx,
                             batch=args.batch, recreate=args.recreate, resume=args.resume,
                             start_row=args.start_row)
        grand_total += n
        print("  " + _INDEX_PREFIX + name + ": " + str(n) + " docs.")

    for name in derived:
        grand_total += _DERIVED_HANDLERS[name](base, args)

    print("Ingestion finished: " + str(grand_total) + " docs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
