# Container for the insider-threat-cert project.
# Python 3.12 + pandas, dependencies declared with uv. Includes tar/bzip2 to
# download and extract the CERT dataset (multi-stream .tar.bz2) inside the container.
FROM python:3.12-slim

# System tools to download/extract the dataset.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tar bzip2 \
    && rm -rf /var/lib/apt/lists/*

# uv (declarative dependency manager) - official binary.
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /uvx /usr/local/bin/

ENV UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependency layer (cacheable): manifests only first.
COPY pyproject.toml uv.lock LICENSE README.md ./
RUN uv sync --frozen --no-install-project

# Project code. The dataset is NOT copied into the image: it is downloaded to
# data/ at runtime and accessed through the docker-compose bind mount.
COPY src/ ./src/
COPY analyses/ ./analyses/
COPY tests/ ./tests/
COPY scripts/ ./scripts/

# Install the insider_threat package into the environment.
RUN uv sync --frozen

# Non-root user that owns /app.
RUN useradd --create-home --uid 1000 app \
    && chown -R app:app /app
USER app

# Keep the service alive for `docker compose run --rm app <cmd>`.
CMD ["sleep", "infinity"]
