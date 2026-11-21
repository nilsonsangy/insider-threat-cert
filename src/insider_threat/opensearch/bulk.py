"""insider_threat.opensearch.bulk: HTTP transport, index lifecycle and the _bulk API."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from insider_threat.opensearch.mappings import MAPPINGS, index_name

__all__ = ["normalize_host", "request", "create_index", "finalize_index", "send_bulk",
           "stored_count", "stored", "bulk_documents"]

_TIMEOUT = 120


def normalize_host(host: str) -> str:
    """``localhost:9200`` -> ``http://localhost:9200``."""
    host = host.strip()
    if not host.startswith(("http://", "https://")):
        host = "http://" + host
    return host.rstrip("/")


def request(method, url, *, data=None, content_type=None):
    r = urllib.request.Request(url, data=data, method=method)
    if content_type:
        r.add_header("Content-Type", content_type)
    with urllib.request.urlopen(r, timeout=_TIMEOUT) as resp:
        return resp.status, resp.read()


def _delete_index(base, index):
    try:
        request("DELETE", base + "/" + index)
    except urllib.error.HTTPError as e:
        if e.code != 404:  # 404 = index does not exist
            raise


def create_index(base, name, *, recreate=False):
    """Create ``cert-<name>`` with its mapping and refresh off (kept if it exists)."""
    index = index_name(name)
    if recreate:
        _delete_index(base, index)
    body = json.dumps({
        "settings": {"number_of_replicas": 0, "refresh_interval": "-1"},
        "mappings": {"properties": MAPPINGS[name]},
    }).encode("utf-8")
    try:
        request("PUT", base + "/" + index, data=body, content_type="application/json")
    except urllib.error.HTTPError as e:
        if e.code != 400:  # 400 = index already exists
            raise


def finalize_index(base, index):
    """Turn refresh back on and force a refresh so documents become searchable."""
    body = json.dumps({"index": {"refresh_interval": "1s"}}).encode("utf-8")
    try:
        request("PUT", base + "/" + index + "/_settings", data=body, content_type="application/json")
        request("POST", base + "/" + index + "/_refresh")
    except urllib.error.URLError:
        pass


def send_bulk(base, index, ndjson_lines) -> int:
    """Send one _bulk request. Returns the number of documents that already existed.

    A ``create`` action on an existing ``_id`` returns a 409 conflict: the stored
    document is kept untouched and the conflict is counted, not raised.
    """
    body = ("".join(ndjson_lines)).encode("utf-8")
    _status, resp = request("POST", base + "/_bulk", data=body,
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


def stored_count(base, index) -> int:
    """Refresh ``index`` and return how many documents it holds (0 if it does not exist)."""
    try:
        request("POST", base + "/" + index + "/_refresh")
        _status, resp = request("GET", base + "/" + index + "/_count")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return 0
        raise
    return int(json.loads(resp).get("count", 0))


def stored(base, index, doc_id) -> bool:
    """True when ``index`` holds a document with ``_id`` = ``doc_id``."""
    try:
        request("GET", base + "/" + index + "/_doc/" + urllib.request.quote(doc_id, safe=""))
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise


def bulk_documents(base, name, documents, *, batch, recreate) -> int:
    """Index ``(id, doc)`` pairs into ``cert-<name>`` and finalize the index."""
    index = index_name(name)
    create_index(base, name, recreate=recreate)
    buffer: list[str] = []
    total = 0
    for doc_id, doc in documents:
        buffer.append(json.dumps({"index": {"_index": index, "_id": doc_id}}) + "\n")
        buffer.append(json.dumps(doc, ensure_ascii=False) + "\n")
        total += 1
        if len(buffer) >= batch * 2:
            send_bulk(base, index, buffer)
            buffer.clear()
    if buffer:
        send_bulk(base, index, buffer)
    finalize_index(base, index)
    return total