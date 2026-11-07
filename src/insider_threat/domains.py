"""insider_threat.domains: suspicious web categories for the CERT r4.2 HTTP log.

The lists below contain only domains that actually occur in the r4.2
``http.csv`` (475 distinct hosts across 28,434,423 requests). They are grouped
by what the site is, independently of the answer key:

- ``job_site``: job search and applicant-tracking sites. Suggests the user is
  planning to leave.
- ``leak_site``: public leak platforms. Suggests intent to disclose data.
- ``cloud_storage``: personal file hosting / transfer services. Possible
  exfiltration outside the perimeter.
- ``spyware``: keylogger and covert-monitoring software vendors. Suggests
  intent to capture other users' credentials or activity.

Matching is done on the URL host (``www.`` removed), including subdomains, so it
is exact and fast enough to classify the full log.
"""

from __future__ import annotations

import re

import pandas as pd

CATEGORIES: dict[str, tuple[str, ...]] = {
    "job_site": (
        "careerbuilder.com",
        "monster.com",
        "simplyhired.com",
        "indeed.com",
        "job-hunt.org",
        "jobhuntersbible.com",
        "taleo.net",
    ),
    "leak_site": (
        "wikileaks.org",
    ),
    "cloud_storage": (
        "dropbox.com",
        "yousendit.com",
        "mediafire.com",
        "megaupload.com",
        "filesonic.com",
        "fileserve.com",
        "4shared.com",
    ),
    "spyware": (
        "dailykeylogger.com",
        "keylogpc.com",
        "actualkeylogger.com",
        "best-spy-soft.com",
        "refog.com",
        "relytec.com",
        "softactivity.com",
        "spectorsoft.com",
        "webwatchernow.com",
        "actionalert.com",
    ),
}

_HOST_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?(?:www\.)?([^/:?#]+)", re.IGNORECASE)


def host_of(url: str) -> str:
    """Return the lowercase host of a URL without a leading ``www.``."""
    m = _HOST_RE.match(str(url or "").strip())
    return m.group(1).lower() if m else ""


def category_of_host(host: str) -> str | None:
    """Return the category of a host (exact domain or subdomain), or ``None``."""
    for category, domains in CATEGORIES.items():
        for d in domains:
            if host == d or host.endswith("." + d):
                return category
    return None


def classify_url(url: str) -> str | None:
    """Return the suspicious category of a URL, or ``None``."""
    return category_of_host(host_of(url))


def is_suspicious(url: str) -> bool:
    """Return True if the URL belongs to any suspicious category."""
    return classify_url(url) is not None


def classify_series(urls: pd.Series) -> pd.Series:
    """Vectorized :func:`classify_url` over a Series of URLs (``None`` = benign)."""
    hosts = urls.str.extract(_HOST_RE, expand=False).str.lower()
    unique = {h: category_of_host(h) for h in hosts.dropna().unique()}
    return hosts.map(unique).astype(object).where(lambda c: c.notna(), None)
