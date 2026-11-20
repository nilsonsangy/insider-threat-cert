"""insider_threat.mass_email: recipient counting and mass-email criterion.

Pure, deterministic module: no network or disk I/O and no pandas dependency.

Key conventions
---------------
- Address fields (``to``, ``cc``, ``bcc``) hold addresses separated by ``;``.
  Empty entries and surrounding whitespace are ignored.
- The recipient count of an email is the total number of addresses across the
  three fields.
- An email is a **mass email** when its recipient count is greater than or
  equal to ``MASS_EMAIL_MIN_RECIPIENTS``.
"""

from __future__ import annotations

MASS_EMAIL_MIN_RECIPIENTS = 8


def split_addresses(value: str) -> list[str]:
    """Split a ``;``-separated address field, dropping empty entries and spaces."""
    if not value:
        return []
    return [part.strip() for part in value.split(";") if part.strip()]


def recipient_count(to: str, cc: str = "", bcc: str = "") -> int:
    """Return the total number of addresses across ``to``, ``cc`` and ``bcc``."""
    return len(split_addresses(to)) + len(split_addresses(cc)) + len(split_addresses(bcc))


def is_mass_email(recipients: int, minimum: int = MASS_EMAIL_MIN_RECIPIENTS) -> bool:
    """Return True when ``recipients`` reaches the ``minimum`` threshold."""
    return recipients >= minimum
