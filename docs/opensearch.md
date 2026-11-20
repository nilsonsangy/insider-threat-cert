# OpenSearch and OpenSearch Dashboards

Guide to ingest the CERT r4.2 sources into OpenSearch and explore them in
OpenSearch Dashboards. The analyses in `analyses/` and the tests do not depend
on this path.

## Prerequisites

- The dataset downloaded and extracted (`data/r4.2/` present). See the main
  [README](../README.md).
- A `.env` file created from `.env.example`.
- Docker with at least 4 GB of memory. On Linux, OpenSearch may require
  `sudo sysctl -w vm.max_map_count=262144`.

## 1. Start OpenSearch and Dashboards

```powershell
docker compose up -d
```

The `opensearch` service reports healthy when the cluster is at least yellow.
Dashboards starts after that. To check the REST API:

```powershell
curl http://localhost:9200
```

Ports and heap size come from `.env` (`OPENSEARCH_PORT`,
`OPENSEARCH_DASHBOARDS_PORT`, `OPENSEARCH_HEAP`).

## 2. Ingest the sources

```powershell
uv run python scripts/ingest_opensearch.py
```

Without `--only`, the script creates and fills five indices from the CSV files
(`cert-logon`, `cert-device`, `cert-file`, `cert-email`, `cert-http`) and then
the two derived indices (`cert-copy-daily`, `cert-risk`). The load uses the
`_bulk` API with deterministic document ids, so repeating it does not duplicate
documents. All 28 million HTTP requests are ingested, which makes `http.csv`
the longest step.

| Option | Effect |
|---|---|
| `--only logon,http` | Ingests only the listed targets: `logon`, `device`, `file`, `email`, `http`, `copy-daily`, `risk`. |
| `--recreate` | Deletes the selected indices before creating them again. Required to apply a new mapping over indices created earlier. |
| `--resume` | Continues an interrupted load from the last confirmed batch (checkpoint `data/.ingest-<source>.json` with the byte offset). Without a checkpoint, the start is the number of stored documents, located by a fast newline count. The row before the start must be stored and the row at it must not be; the rest is sent as `create`, which never overwrites a document. No row is sent twice. |
| `--start-row N` | Starts one source (`--only <source>`) at data row `N` (0-based), with the same checks as `--resume`. |
| `--host HOST:PORT` | Overrides `OPENSEARCH_HOST` (default `localhost:9200`). |
| `--batch N` | `_bulk` batch size (default 10000). |

### Derived fields

Added during ingestion, from the same rules used by the analyses:

| Index | Field | Meaning |
|---|---|---|
| all sources | `off_hours` | `true` when the event hour is before 07h or from 19h on, using the date as recorded (no time zone). |
| all sources | `role` | Role of the user in the most recent LDAP snapshot. Omitted when the user is not in LDAP. |
| `cert-email` | `recipients` | Sum of addresses in `to`, `cc` and `bcc`. |
| `cert-email` | `to`, `cc`, `bcc` | Lists of addresses (one value per address). |
| `cert-http` | `domain` | Host extracted from the URL. |
| `cert-http` | `category` | `job_site`, `leak_site`, `cloud_storage` or `spyware`, omitted for other hosts. The `url` field stays in `_source` and is not indexed. |

### New indices

| Index | One document per | Fields |
|---|---|---|
| `cert-copy-daily` | user and day | `user`, `role`, `date`, `copies` |
| `cert-risk` | user | `user`, `role`, the five boolean signals (`off_hours_logon`, `off_hours_usb`, `copy_above_baseline`, `job_or_cloud_web`, `leak_or_spyware_web`), `score`, `in_answer_key`, `scenario` |

OpenSearch does not join indices. These two indices hold the per-user and
per-user-per-day aggregates that cannot be computed across the event indices.
Building `cert-risk` reads `http.csv` once (the result is cached in
`data/derived/`).

## 3. Explore in Dashboards

Open <http://localhost:5601>.

### Time zone

The dataset dates carry no time zone. To display them as recorded, open
**Dashboards Management → Advanced settings** and set `dateFormat:tz` to `UTC`.

### Index patterns

Under **Dashboards Management → Index patterns**, create one pattern per index
(for example `cert-http`, `cert-device`, `cert-risk`), or a single `cert-*`
pattern. Choose `date` as the time field. `cert-risk` has no time field.

### Discover

Select an index pattern, set the time range to cover 2010-01-01 to 2011-06-01,
and query with DQL. Examples:

- `category:leak_site` on `cert-http`: visits to leak sites.
- `category:spyware` on `cert-http`: visits to keylogger vendors.
- `activity:Connect and off_hours:true` on `cert-device`: USB connections
  outside work hours.
- `recipients >= 8` on `cert-email`: messages with many recipients.
- `score >= 6` on `cert-risk`: users with a high correlated score.

### Visualizations

Under **Visualize**, create charts from the index patterns, for example a
data table of `user` by `copies` on `cert-copy-daily`, or a bar chart of
`category` counts on `cert-http`.

### Dashboards

Under **Dashboards**, add the saved visualizations and saved searches to a
single dashboard and keep the time range and filters shared across panels.

## 4. Shut down

```powershell
docker compose down -v
```

The `-v` option removes the named volume, so the indices are deleted and the
next start needs a new ingestion.
