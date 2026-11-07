# Ingesting the sources into OpenSearch (optional)

Step-by-step guide to start OpenSearch + OpenSearch Dashboards and explore the
CERT r4.2 data visually. This is an **optional, isolated** path: the analyses and
tests run without it, and nothing in `analyses/` or `tests/` uses it.

## Prerequisites

- The dataset already downloaded and extracted (`data/r4.2/` present). See the
  main README.
- Enough memory for OpenSearch (the service uses `-Xms512m -Xmx512m` in the env
  file and `2g` in `docker-compose.yml`). On Linux you may need
  `sudo sysctl -w vm.max_map_count=262144`.

## 1. Start OpenSearch + Dashboards

The services live under the `opensearch` profile, so the default `up` does not
start them:

```powershell
docker compose --profile opensearch up -d
```

Wait for port `9200` to respond:

```powershell
curl http://localhost:9200
```

## 2. Ingest the sources

The script creates one index per source (`cert-logon`, `cert-device`,
`cert-file`, `cert-email`, `cert-http`) and indexes through the `_bulk` API.
From inside the compose network, the host is `opensearch:9200`:

```powershell
docker compose run --rm app python scripts/ingest_opensearch.py --host opensearch:9200
```

The full dataset is ingested (all 28M HTTP requests included), which takes a while for `http.csv`. Use `--only SOURCE` to ingest a single source, for example `--only logon`.

## 3. Explore in Dashboards

Open `http://localhost:5601`. Under **Dashboards Management → Index patterns**,
create `cert-*` with `date` as the time field and explore in **Discover**.
Examples:

- `url: *indeed* OR url: *dropbox*` on `cert-http` → suspicious browsing.
- `activity: Connect` on `cert-device` → USB connections.
- `cert-file` → file copies (correlate with `cert-device` by user/time).

## 4. Shut down

```powershell
docker compose --profile opensearch down -v
```
