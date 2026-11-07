# Insider Threat: CERT Insider Threat Dataset (r4.2) Analysis

A reproducible analysis of the **CERT Insider Threat Test Dataset** (release
**r4.2**, Carnegie Mellon University / CERT). The repository walks through a
chain of detection analyses over the **complete, real dataset**, from suspicious
web browsing to a correlated per-user risk score, and validates the result
against the dataset's official insider answer key.

There are no samples, row limits or fabricated data anywhere in this
repository: every analysis and every test reads the full r4.2 files.

The dataset is also mirrored on Kaggle:
<https://www.kaggle.com/datasets/andrihjonior/cert-insider-threat-dataset-r4-2>.
The download script uses the original KiltHub/CMU source and verifies MD5
checksums.

## The dataset at a glance

| Source | Content | Size |
|---|---|---|
| `logon.csv` | Logon / Logoff events | 56 MB |
| `device.csv` | USB Connect / Disconnect (203,339 connections) | 28 MB |
| `file.csv` | File copies (445,581) | 184 MB |
| `email.csv` | E-mail metadata | 1.3 GB |
| `http.csv` | Web requests (28,434,423, 475 distinct hosts) | 13.9 GB |
| `LDAP/` | 18 monthly snapshots, 1,000 users with role and department | small |
| `answers/insiders.csv` | Answer key: 70 r4.2 insiders in 3 scenarios (30 / 30 / 10) | small |

The r4.2 scenarios, as described by CERT:

1. A user who did not work after hours starts logging on after hours, uses a
   removable drive and uploads data to wikileaks.org, then leaves.
2. A user starts browsing job sites and soliciting employment from a
   competitor, and before leaving copies data to a thumb drive at a markedly
   higher rate than before.
3. A system administrator downloads a keylogger, uses a thumb drive to install
   it on a supervisor's machine, and uses the captured credentials to send an
   alarming mass e-mail.

## Analyses

Six chained analyses, each tied to a MITRE ATT&CK technique:

| # | Analysis | Insider signal | ATT&CK |
|---|---|---|---|
| 1 | Suspicious web browsing | job sites, leak sites, cloud storage, spyware vendors | T1567 |
| 2 | USB exfiltration | file copies made while a USB device is connected | T1052 |
| 3 | Off-hours USB × logon | off-hours USB connection inside the user's own session | T1078 + T1052 |
| 4 | File copies vs. baseline | copy volume above 3x the peer-group (role) norm | T1052 |
| 5 | Correlation and risk score | signals combined into an additive score per user | T1052 / T1567 / T1078 |
| 6 | Validation | ranking and each signal checked against the answer key | n/a |

The suspicious-domain lists in `src/insider_threat/domains.py` contain only
hosts that actually occur in the r4.2 HTTP log, grouped by what the site is:

- `job_site`: careerbuilder, monster, simplyhired, indeed, job-hunt.org,
  jobhuntersbible, taleo
- `leak_site`: wikileaks.org
- `cloud_storage`: dropbox, yousendit, mediafire, megaupload, filesonic,
  fileserve, 4shared
- `spyware`: keylogger and covert-monitoring vendors (dailykeylogger, refog,
  spectorsoft, and others)

Risk score weights (`src/insider_threat/score.py`) are fixed a priori by how
specific each behavior is. They are **not** fitted to the answer key, which is
used only in analysis 6:

| Signal | Weight |
|---|---|
| Logon outside work hours (07h-19h) | +1 |
| Off-hours USB connection inside the user's own logon session | +2 |
| Mean copies/day above 3x the role baseline | +3 |
| Job site or cloud storage browsing (common, weak) | +1 |
| Leak site or spyware browsing (rare, specific) | +3 |

## Results on the full dataset

Output of `python -m analyses.a06_validation` over the complete r4.2 data:

| Signal | Users flagged | Insiders among them | Precision | Recall |
|---|---|---|---|---|
| Off-hours logon | 190 | 42 | 22.1% | 60.0% |
| Off-hours USB in own session | 104 | 42 | 40.4% | 60.0% |
| Copies above 3x role baseline | 47 | 13 | 27.7% | 18.6% |
| Job site / cloud storage browsing | 983 | 69 | 7.0% | 98.6% |
| Leak site / spyware browsing | 40 | 40 | 100.0% | 57.1% |

| Ranking | Value |
|---|---|
| precision@10 | 100.0% |
| precision@30 | 76.7% |
| precision@70 | 57.1% |
| Scenario 1 insiders in the top 70 | 30 / 30 |
| Scenario 2 insiders in the top 70 | 0 / 30 |
| Scenario 3 insiders in the top 70 | 10 / 10 |

What the data shows:

- **Rare, specific behaviors carry the signal.** Every one of the 40 users who
  visited wikileaks.org or a keylogger vendor is an insider (scenarios 1 and 3).
- **Common behaviors are noise on their own.** Job sites and cloud storage are
  visited by 983 of the 1,000 users, so a presence-based signal cannot separate
  scenario 2 insiders from everyone else.
- **USB is the exfiltration channel.** 441,885 of the 445,581 file copies
  (99.2%) happen while a USB device is connected, so in r4.2 `file.csv` is
  effectively a log of copies to removable media.
- **Scenario 2 is not caught by this model (0/30 in the top 70).** Those
  insiders behave like their peers in absolute terms; detecting them needs a
  change-over-time baseline (each user against their own history), which is a
  natural next step for this repository.

---

## Prerequisites

- **Docker Desktop** with **Docker Compose v2**, or **Python 3.12+** with
  [uv](https://docs.astral.sh/uv/).
- About 25 GB of free disk space (4.6 GB download, ~15.5 GB extracted).
- Enough memory to hold the activity sources (the `content` columns are not
  loaded, and `http.csv` is streamed in chunks). If you use Docker Desktop,
  give it a generous memory limit.

```powershell
git clone https://github.com/nilsonsangy/insider-threat-cert.git
cd insider-threat-cert
```

The commands below are for **Windows PowerShell**; they work the same on
Linux/macOS. Each command is shown for Docker; without Docker, replace
`docker compose run --rm app` with `uv run` (run `uv sync` once first).

---

## Part 0: Set up the environment

```powershell
docker compose build app
docker compose up -d app
```

The repository is mounted inside the container at `/app`, so the dataset you
download to `data/` is visible on both sides.

## Part 1: Download the official dataset (CERT r4.2)

```powershell
# show the source, terms of use and what is missing
docker compose run --rm app python scripts/download_cert.py --dry-run

# download (~4.6 GB, MD5-verified) and extract incrementally
docker compose run --rm app python scripts/download_cert.py --extract
```

The CSVs land in `data/r4.2/` and the answer key in `data/answers/`. The whole
`data/` directory is ignored by Git, so the dataset is never committed.

## Part 2: Run the analyses

Run them in order (1 → 6). Every analysis reads the full dataset.

```powershell
docker compose run --rm app python -m analyses.a01_web_browsing
docker compose run --rm app python -m analyses.a02_usb_exfiltration
docker compose run --rm app python -m analyses.a03_off_hours_usb
docker compose run --rm app python -m analyses.a04_file_copy_baseline
docker compose run --rm app python -m analyses.a05_correlation
docker compose run --rm app python -m analyses.a06_validation
```

- Analysis 1 streams all 28M HTTP rows (about 2-3 minutes) and caches the
  per-user counts in `data/derived/web_hits.csv`. Analyses 5 and 6 reuse that
  cache; it is rebuilt automatically if `http.csv` changes, or on demand with
  `--refresh`.
- Analyses 2 to 4 take about 30 seconds each.
- Analysis 3 accepts custom work hours: `--work-hours 8-18`.
- Analysis 4 accepts a custom threshold: `--factor 2.5`.

### Tests

```powershell
docker compose run --rm app pytest -q
```

The tests run against the real dataset only. They pin facts of the r4.2
release (row counts, 1,000 users, 70 insiders) and check the analyses end to
end. If the dataset has not been downloaded, they fail with instructions
instead of being skipped.

## Part 3: Visualize in OpenSearch (optional)

```powershell
docker compose --profile opensearch up -d
docker compose run --rm app python scripts/ingest_opensearch.py --host opensearch:9200
# open http://localhost:5601
```

Create a `cert-*` index pattern with `date` as the time field and explore in
**Discover**, for example `url: *wikileaks*` on `cert-http` or
`activity: Connect` on `cert-device`. Details are in
[`compose/opensearch/README-ingest.md`](./compose/opensearch/README-ingest.md).

```powershell
docker compose --profile opensearch down -v
```

## Shut down

```powershell
docker compose down -v --remove-orphans
```

---

## Repository layout

```text
insider-threat-cert/
├── README.md                 # this guide
├── LICENSE                   # MIT (project code)
├── pyproject.toml / uv.lock  # dependencies (pandas, pytest) via uv
├── Dockerfile                # Python 3.12 + uv
├── docker-compose.yml        # `app` service (default) + `opensearch` profile
├── data/                     # downloaded dataset and derived cache (gitignored)
├── src/insider_threat/       # core library: loaders, timewin, baseline, score, domains
├── analyses/                 # a01..a06
├── tests/                    # tests over the real dataset
├── scripts/                  # download_cert.py and ingest_opensearch.py
└── compose/opensearch/       # optional OpenSearch path
```

## Data: source, license and credits

The dataset is **not** versioned in this repository. You download it from the
official source, which respects the dataset's terms of use.

- **Source:** *Insider Threat Test Dataset*, Carnegie Mellon University (CERT
  Division), distributed on KiltHub:
  <https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247>
  (DOI 10.1184/R1/12841247).
- **Reference:** Glasser, J.; Lindauer, B. *Bridging the Gap: A Pragmatic
  Approach to Generating Insider Threat Data*. IEEE Security and Privacy
  Workshops, 2013.
- **Data generator:** the dataset was generated by **ExactData, LLC**
  (© 2011, all rights reserved) under agreement with CMU/SEI. It is synthetic by
  design (no real employees), with insider scenarios injected by CERT. Respect
  the license included in the dataset (`r4.2/license.txt`).

The **code** in this repository is by **Nilson Sangy** and is under the
[MIT license](./LICENSE). The MIT license covers the code, not the dataset.
