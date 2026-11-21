"""insider_threat.opensearch.resume: continuing an interrupted load without resending rows.

Rows are sent in file order, one _bulk at a time, with the CSV ``id`` as
``_id``. After each confirmed batch a checkpoint records the byte offset of the
next row. A resumed load jumps straight to that offset (or, without a
checkpoint, to the row given by the number of stored documents, located by a
fast newline count), checks that the row before it is stored and the row at it
is not, and sends the rest as ``create``, which never overwrites a document.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from insider_threat import loaders as _loaders
from insider_threat.opensearch.bulk import stored, stored_count

__all__ = ["checkpoint_path", "read_checkpoint", "write_checkpoint", "offset_of_row",
           "rows_from", "first_id_at", "resume_point"]

_CHUNK = 64 * 1024 * 1024


def checkpoint_path(name, data_dir=None) -> Path:
    """Checkpoint of the last confirmed batch, kept in the (unversioned) data folder."""
    return _loaders.data_root(data_dir) / f".ingest-{name}.json"


def read_checkpoint(name, path, data_dir=None) -> dict | None:
    """Stored checkpoint of ``name``, or None if missing, unreadable or for another CSV."""
    cp = checkpoint_path(name, data_dir)
    if not cp.is_file():
        return None
    try:
        data = json.loads(cp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    st = Path(path).stat()
    if data.get("size") != st.st_size or data.get("mtime") != int(st.st_mtime):
        return None  # the CSV changed: the stored offset is no longer valid
    return data


def write_checkpoint(name, path, offset, rows, data_dir=None) -> None:
    st = Path(path).stat()
    data = {"source": name, "offset": offset, "rows": rows,
            "size": st.st_size, "mtime": int(st.st_mtime)}
    checkpoint_path(name, data_dir).write_text(json.dumps(data), encoding="utf-8")


def offset_of_row(path, row) -> int:
    """Byte offset where data row ``row`` (0-based, header excluded) starts.

    Counts newlines in large binary blocks, without parsing the CSV, so it costs
    a few seconds even for the 14 GB http.csv. It assumes one physical line per
    row; ``resume_point`` confirms the result against the stored documents.
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


def rows_from(path, offset):
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


def first_id_at(path, offset) -> str | None:
    for row, _end in rows_from(path, offset):
        return row.get("id") or None
    return None


def resume_point(base, index, name, path, start_row=None, *, log=print):
    """Return ``(offset, rows_before)`` for a resumed load, or raise if unsafe.

    Uses the checkpoint when it exists; otherwise ``start_row`` or, by default,
    the number of stored documents. The row right before the start must be
    stored and the row at the start must not be.
    """
    cp = read_checkpoint(name, path) if start_row is None else None
    if cp:
        offset, rows = cp["offset"], cp["rows"]
        log(f"    {name}: checkpoint found, {rows} rows confirmed.")
        prev_id = None
    else:
        rows = start_row if start_row is not None else stored_count(base, index)
        if rows == 0:
            return 0, 0
        # One newline count: the row before the start, then the start right after it.
        before = offset_of_row(path, rows - 1)
        prev_id, offset = None, before
        for row, end in rows_from(path, before):
            prev_id, offset = row.get("id") or None, end
            break
        log(f"    {name}: starting at row {rows} (byte {offset}).")
    next_id = first_id_at(path, offset)
    if prev_id is not None and not stored(base, index, prev_id):
        raise RuntimeError(f"row {rows - 1} ({prev_id}) is not stored: the start point is wrong.")
    if next_id is not None and stored(base, index, next_id):
        raise RuntimeError(f"row {rows} ({next_id}) is already stored: the start point is wrong.")
    return offset, rows