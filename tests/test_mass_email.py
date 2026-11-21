"""Property tests for recipient counting, the mass-email criterion and ``a07`` candidates."""
from __future__ import annotations

import pandas as pd
from hypothesis import given, settings, strategies as st

import a07_mass_email  # scripts/ is on the test path (see pyproject)
from insider_threat.mass_email import (
    MASS_EMAIL_MIN_RECIPIENTS,
    is_mass_email,
    recipient_count,
)

ADDRESS = st.from_regex(r"[a-z]{1,5}@[a-z]{1,5}\.com", fullmatch=True)
BLANK = st.text(alphabet=" ", max_size=3)
PAD = st.text(alphabet=" ", max_size=2)


@st.composite
def address_field(draw):
    """Return ``(field, n_addresses)`` with blanks and padding mixed in."""
    tokens = draw(st.lists(st.one_of(ADDRESS.map(lambda a: (a, 1)), BLANK.map(lambda b: (b, 0))), max_size=6))
    padded = [draw(PAD) + text + draw(PAD) for text, _ in tokens]
    return ";".join(padded), sum(n for _, n in tokens)


@settings(max_examples=5, deadline=None)
@given(to=address_field(), cc=address_field(), bcc=address_field())
def test_recipient_count_sums_fields_ignoring_blanks(to, cc, bcc):
    assert recipient_count(to[0], cc[0], bcc[0]) == to[1] + cc[1] + bcc[1]


@settings(max_examples=5, deadline=None)
@given(n=st.integers(min_value=0, max_value=30))
def test_is_mass_email_exactly_at_threshold(n):
    assert is_mass_email(n) == (n >= MASS_EMAIL_MIN_RECIPIENTS == 8)


@settings(max_examples=5, deadline=None)
@given(rows=st.lists(
    st.tuples(
        st.sampled_from(["U0", "U1", "U2", "U3"]),
        st.sampled_from(["PC0", "PC1"]),
        st.sampled_from(["Connect", "Disconnect"]),
        st.integers(min_value=-600, max_value=3600),  # minutes relative to the email
    ),
    max_size=12,
))
def test_a07_candidates_match_definition(rows):
    sent = pd.Timestamp("2010-06-15 12:00:00")
    email = pd.DataFrame([{
        "date": sent, "user": "U0", "pc": "PC0",
        "to": ";".join(f"r{i}@x.com" for i in range(MASS_EMAIL_MIN_RECIPIENTS)),
        "cc": "", "bcc": "", "size": "100", "attachments": "0",
    }])
    device = pd.DataFrame(
        [{"date": sent - pd.Timedelta(minutes=m), "user": u, "pc": pc, "activity": act}
         for u, pc, act, m in rows],
        columns=["date", "user", "pc", "activity"],
    )

    result = a07_mass_email.run({"email": email, "device": device})

    expected = sorted(
        (u, sent - pd.Timedelta(minutes=m)) for u, pc, act, m in rows
        if act == "Connect" and pc == "PC0" and u != "U0" and 0 <= m <= 48 * 60
    )
    assert len(result) == 1
    actual = sorted((c.user, c.connect_ts) for c in result[0].candidates)
    assert actual == expected
