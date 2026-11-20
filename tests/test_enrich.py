"""Property test for the derived fields produced by ``enrich_row``."""
from __future__ import annotations

import copy

import pandas as pd
from hypothesis import given, settings, strategies as st

from insider_threat.domains import category_of_host, host_of
from insider_threat.enrich import EnrichContext, enrich_row
from insider_threat.mass_email import recipient_count, split_addresses
from insider_threat.timewin import is_off_hours

ROLES = {"U1": "Engineer", "U2": "Manager"}
URLS = [
    "http://www.example.com/page",
    "http://wikileaks.org/leak",
    "https://jobs.example.org/x?q=1",
]
FIELD = st.lists(st.sampled_from(["a@x.com", "b@y.com", " ", " c@z.com "]), max_size=5).map(";".join)

DOC = st.fixed_dictionaries({
    "date": st.datetimes(min_value=pd.Timestamp("2010-01-01"), max_value=pd.Timestamp("2011-12-31")).map(
        lambda d: d.strftime("%Y-%m-%dT%H:%M:%S")),
    "user": st.sampled_from(["U1", "U2", "U9"]),
    "to": FIELD, "cc": FIELD, "bcc": FIELD,
    "size": st.one_of(st.just(""), st.integers(0, 10**6).map(str)),
    "attachments": st.one_of(st.just(""), st.integers(0, 5).map(str)),
    "url": st.sampled_from(URLS),
})


@settings(max_examples=5, deadline=None)
@given(source=st.sampled_from(["cert-email", "cert-http", "cert-logon"]), doc=DOC)
def test_enrich_row_derived_fields_and_input_untouched(source, doc):
    before = copy.deepcopy(doc)
    ctx = EnrichContext(roles=ROLES)

    out = enrich_row(source, doc, ctx)

    assert doc == before
    assert out["off_hours"] == is_off_hours(pd.Timestamp(doc["date"]))
    assert ("role" in out) == (doc["user"] in ROLES)
    if "role" in out:
        assert out["role"] == ROLES[doc["user"]]
    if source == "cert-email":
        assert out["to"] == split_addresses(doc["to"])
        assert out["cc"] == split_addresses(doc["cc"])
        assert out["bcc"] == split_addresses(doc["bcc"])
        assert out["recipients"] == recipient_count(doc["to"], doc["cc"], doc["bcc"])
        assert out["size"] == int(doc["size"] or 0)
        assert out["attachments"] == int(doc["attachments"] or 0)
    elif source == "cert-http":
        assert out["domain"] == host_of(doc["url"])
        category = category_of_host(out["domain"])
        assert out.get("category") == category
        assert ("category" in out) == (category is not None)
