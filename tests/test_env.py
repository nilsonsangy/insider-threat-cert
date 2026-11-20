"""Property test for the configuration precedence of ``insider_threat.env``."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest import mock

from hypothesis import given, settings, strategies as st

from insider_threat import env

KEY = "INSIDER_THREAT_TEST_KEY"
VALUES = st.one_of(st.none(), st.text(alphabet="abcXYZ0129._-", max_size=6))


@settings(max_examples=5, deadline=None)
@given(process=VALUES, dotenv=VALUES, default=st.text(alphabet="abc", min_size=1, max_size=4))
def test_precedence_process_then_dotenv_then_default(process, dotenv, default):
    """Process value wins, then ``.env``, then default; empty counts as absent."""
    with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, clear=False):
        os.environ.pop(KEY, None)
        if process is not None:
            os.environ[KEY] = process
        path = Path(tmp) / ".env"
        if dotenv is not None:
            path.write_text(f"{KEY}={dotenv}\n", encoding="utf-8")

        env.load_env(path)

        expected = process or dotenv or default
        assert env.get(KEY, default) == expected
        if process:
            assert os.environ[KEY] == process  # an existing value is never overwritten
