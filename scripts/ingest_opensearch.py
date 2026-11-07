#!/usr/bin/env python3
"""Ingest the CERT r4.2 sources into OpenSearch (optional exploratory path).

By DEFAULT it ingests the ENTIRE dataset. The activity sources (logon, device,
file, email) and http.csv are read in STREAMING mode (chunks) and indexed batch
by batch through the _bulk API, so the large files (http ~14 GB) are never
loaded into memory.

Creates one index per source: cert-logon, cert-device, cert-file, cert-email,
cert-http. Uses only the stdlib (urllib) for HTTP transport.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime
import urllib.error
import urllib.request
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DATA = _REPO_ROOT / "data" / "r4.2"
_INDEX_PREFIX = "cert-"
_DEFAULT = "localhost:9200"
_TIMEOUT = 120

# Sources to ingest and their columns (r4.2 schema).
SOURCES = {
    "logon": ["id", "date", "user", "pc", "activity"],
    "device": ["id", "date", "user", "pc", "activity"],
    "file": ["id", "date", "user", "pc", "filename", "content"],
    "email": ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments", "content"],
    "http": ["id", "date", "user", "pc", "url", "content"],
}
# Long-text columns we do NOT index (saves space/time): the synthetic body of
# file/email/http is irrelevant for exploring the signals.
DISCARD = {"content"}


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


def _create_index(base, index, columns):
    # Explicit mapping: `date` as a date type (ISO-8601); other fields as keyword
    # (good for exact filters on user/pc/activity/url/filename).
    props = {}
    for c in columns:
        if c in DISCARD:
            continue
        if c == "date":
            props[c] = {"type": "date"}
        else:
            props[c] = {"type": "keyword"}
    body = json.dumps({
        "settings": {"number_of_replicas": 0, "refresh_interval": "-1"},
        "mappings": {"properties": props},
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
    body = ("".join(ndjson_lines)).encode("utf-8")
    _status, resp = _request("POST", base + "/_bulk", data=body,
                             content_type="application/x-ndjson")
    payload = json.loads(resp)
    if payload.get("errors"):
        for item in payload.get("items", []):
            action = next(iter(item.values()))
            if action.get("error"):
                raise RuntimeError(f"OpenSearch rejected a document in '{index}': {action['error']}")


def _index_streaming(base, name, columns, path, *, batch=10000):
    index = _INDEX_PREFIX + name
    _create_index(base, index, columns)
    keep = [c for c in columns if c not in DISCARD]
    default_meta = json.dumps({"index": {"_index": index}}) + "\n"

    total = 0
    buffer: list[str] = []
    with open(path, "r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            doc = {c: row.get(c, "") for c in keep}
            if "date" in doc:
                iso = _iso_date(doc["date"])
                if iso is not None:
                    doc["date"] = iso
                else:
                    doc.pop("date", None)
            # Deterministic _id = the unique CERT row id. This makes ingestion
            # IDEMPOTENT: re-indexing the same row overwrites it (no duplicates),
            # so the load can be resumed after any interruption.
            doc_id = row.get("id") or None
            if doc_id:
                meta = json.dumps({"index": {"_index": index, "_id": doc_id}}) + "\n"
            else:
                meta = default_meta
            buffer.append(meta)
            buffer.append(json.dumps(doc, ensure_ascii=False) + "\n")
            total += 1
            if len(buffer) >= batch * 2:
                _send_bulk(base, index, buffer)
                buffer.clear()
                if total % 100000 == 0:
                    print(f"    {name}: {total} docs...", flush=True)
    if buffer:
        _send_bulk(base, index, buffer)
    _finalize_index(base, index)
    return total


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ingest_opensearch.py",
                                description="Ingest the r4.2 sources into OpenSearch (the full dataset).")
    p.add_argument("--host", default=os.environ.get("OPENSEARCH_HOST", _DEFAULT))
    p.add_argument("--batch", type=int, default=10000, help="_bulk batch size.")
    p.add_argument("--only", default=None,
                   help="Optional: ingest a single source (e.g. --only http).")
    args = p.parse_args(argv)

    base = _normalize_host(args.host)
    try:
        _request("GET", base + "/")
    except urllib.error.URLError as e:
        print("ERROR: could not connect to OpenSearch at " + base + ": "
              + str(getattr(e, "reason", e)) + ". Start it with "
              + "'docker compose --profile opensearch up -d'.", file=sys.stderr)
        return 1

    targets = [args.only] if args.only else list(SOURCES.keys())
    print("Connected to " + base + ". Ingesting (the full dataset)...")
    grand_total = 0
    for name in targets:
        if name not in SOURCES:
            print("  unknown source: " + str(name), file=sys.stderr)
            return 2
        path = _DATA / (name + ".csv")
        if not path.is_file():
            print("  " + name + ": file missing (" + str(path) + "), skipping.")
            continue
        print("  " + _INDEX_PREFIX + name + ": indexing everything...")
        n = _index_streaming(base, name, SOURCES[name], path, batch=args.batch)
        grand_total += n
        print("  " + _INDEX_PREFIX + name + ": " + str(n) + " docs.")

    print("Ingestion finished: " + str(grand_total) + " docs. Explore at http://localhost:5601")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
