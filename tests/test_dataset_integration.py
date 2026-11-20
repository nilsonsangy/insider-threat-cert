"""Tests on the CERT r4.2 dataset.

The dataset must be downloaded and extracted first
(``uv run python scripts/download_cert.py --extract``). If it is missing, every
test fails with a clear message instead of being skipped, so a green run always
means the checks ran against the dataset files.

Pinned numbers are facts of the published r4.2 release (row counts, number of
users, number of insiders) and of the analyses run over it.
"""

from __future__ import annotations

import pandas as pd
import pytest

from insider_threat import domains, loaders, timewin
from insider_threat.baseline import copies_per_day, individual_baseline, peer_group_baseline
from insider_threat.score import WEIGHTS


@pytest.fixture(scope="session")
def sources():
    try:
        return loaders.load_sources()
    except FileNotFoundError as exc:
        pytest.fail(f"CERT r4.2 files not found ({exc}). Run: uv run python scripts/download_cert.py --extract")


@pytest.fixture(scope="session")
def sessions(sources):
    return timewin.logon_sessions(sources["logon"])


@pytest.fixture(scope="session")
def web_hits():
    from analyses import a01_web_browsing
    return a01_web_browsing.web_hits()


@pytest.fixture(scope="session")
def web_users(web_hits):
    from analyses import a01_web_browsing
    return a01_web_browsing.web_users_by_category(web_hits)


# --- dataset facts -----------------------------------------------------------

def test_row_counts(sources):
    assert len(sources["file"]) == 445_581
    connects = sources["device"]["activity"].str.lower().eq("connect").sum()
    assert connects == 203_339
    assert sources["ldap"]["user_id"].nunique() == 1000


def test_schemas(sources):
    assert set(sources) == {"logon", "device", "file", "email", "ldap", "answer_key"}
    assert list(sources["logon"].columns) == ["id", "date", "user", "pc", "activity"]
    assert list(sources["file"].columns) == ["id", "date", "user", "pc", "filename"]
    assert {"user_id", "role"} <= set(sources["ldap"].columns)


def test_answer_key_r42(sources):
    key = sources["answer_key"]
    assert len(key) == 70
    assert (key["dataset"] == "4.2").all()
    assert key.groupby("scenario")["user"].nunique().to_dict() == {"1": 30, "2": 30, "3": 10}
    assert set(key["user"]) <= set(sources["ldap"]["user_id"])


def test_dates_parsed(sources):
    for name in ("logon", "device", "file", "email"):
        col = sources[name]["date"]
        assert pd.api.types.is_datetime64_any_dtype(col), name
        assert col.notna().all(), name
        assert col.min() >= pd.Timestamp("2010-01-01") and col.max() < pd.Timestamp("2011-06-01"), name


# --- core library on the dataset -----------------------------------------------

def test_logon_sessions_well_formed(sources, sessions):
    assert len(sessions) > 0
    assert (sessions["end"] >= sessions["start"]).all()
    # Every session belongs to a (user, pc) pair that appears in logon.csv.
    pairs = set(zip(sources["logon"]["user"], sources["logon"]["pc"]))
    assert set(zip(sessions["user"], sessions["pc"])) <= pairs


def test_session_index_matches_scan(sources, sessions):
    index = timewin.SessionIndex(sessions)
    sample = sources["device"].iloc[::25_000]
    for user, pc, ts in zip(sample["user"], sample["pc"], sample["date"]):
        assert (index.find(ts, user, pc) is not None) == timewin.within_session(ts, user, pc, sessions)


def test_off_hours_mask_matches_scalar(sources):
    dates = sources["logon"]["date"].iloc[::1000]
    mask = timewin.off_hours_mask(dates)
    assert mask.tolist() == [timewin.is_off_hours(d) for d in dates]


def test_copies_per_day_matches_file_rows(sources):
    assert int(copies_per_day(sources["file"])["copies"].sum()) == len(sources["file"])


def test_peer_group_baseline(sources):
    peer = peer_group_baseline(sources["file"], sources["ldap"])
    individual = individual_baseline(sources["file"])
    assert len(peer) > 0 and (peer > 0).all()
    assert set(peer.index) <= set(sources["ldap"]["role"])
    assert peer.max() <= individual.max()


# --- web categories on the HTTP log --------------------------------------

def test_web_categories_present(web_hits):
    users = web_hits.groupby("category")["user"].nunique().to_dict()
    assert set(users) == set(domains.CATEGORIES)
    assert users["leak_site"] == 30
    assert users["spyware"] == 10


def test_classifier_scalar_and_vectorized_agree():
    chunk = next(loaders.iter_http())
    urls = chunk["url"].iloc[:50_000]
    assert domains.classify_series(urls).tolist() == [domains.classify_url(u) for u in urls]


# --- analyses and validation --------------------------------------------------

def test_analyses_end_to_end(sources, web_hits, web_users):
    from analyses import (a02_usb_exfiltration, a03_off_hours_usb,
                          a04_file_copy_baseline, a05_correlation, a06_validation)

    usb = a02_usb_exfiltration.run(sources)
    assert usb.total_connections == 203_339
    assert 0 < usb.copies_during_usb <= usb.total_copies

    events = a03_off_hours_usb.run(sources)
    assert all(timewin.is_off_hours(e.usb_ts) for e in events)

    flags = a04_file_copy_baseline.run(sources)
    assert flags and all(f.factor > 3.0 for f in flags)

    ranking = a05_correlation.run(sources, web_users=web_users)
    assert ranking == sorted(ranking, key=lambda s: (-s.score, s.user))
    assert all(s.score == sum(s.signals.values()) for s in ranking)
    assert all(set(s.signals) <= set(WEIGHTS) for s in ranking)

    verdicts = a06_validation.run(ranking, sources["answer_key"])
    insiders = set(sources["answer_key"]["user"])
    assert all(v.in_answer_key == (v.user in insiders) for v in verdicts)

    # Headline results: everyone with the leak/spyware web signal is an insider,
    # and the ten highest scores are all insiders.
    leak_users = {s.user for s in ranking if "leak_or_spyware_web" in s.signals}
    assert leak_users and leak_users <= insiders
    assert a06_validation.precision_at(verdicts, 10) == 1.0
