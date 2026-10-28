# STAGE 1 - Base
FROM python:3.11-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Keep Semgrep's pinned dependency tree out of the API interpreter.
COPY backend/scanner-requirements.txt ./scanner-requirements.txt
RUN python -m venv /opt/semgrep \
    && /opt/semgrep/bin/python -m pip install --no-cache-dir -r scanner-requirements.txt
# Build tools and Git are unnecessary for the HTTP-based runtime. Refresh the
# packaging tool's vendored dependencies before removing build-only packages.
RUN python -m pip install --no-cache-dir --upgrade setuptools==84.2.1 \
    && /opt/semgrep/bin/python -m pip install --no-cache-dir --upgrade setuptools==84.2.1 \
    && apt-get purge -y --auto-remove gcc libpq-dev git \
    && rm -rf /var/lib/apt/lists/*
ENV SEMGREP_PATH=/opt/semgrep/bin/semgrep
RUN groupadd --system --gid 10001 zorix \
    && useradd --system --uid 10001 --gid zorix --create-home --home-dir /home/zorix zorix \
    && mkdir -p /app/reports /app/logs \
    && chown zorix:zorix /app/reports /app/logs
ENV HOME=/home/zorix


# STAGE 2 - Development
FROM base AS development

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY backend/ ./backend/
COPY security/ ./security/

COPY docker/backend/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
USER zorix

ENTRYPOINT ["/entrypoint.sh"]


# STAGE 3 - Production
FROM base AS production

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY backend/ ./backend/
COPY security/ ./security/

COPY docker/backend/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
USER zorix

ENTRYPOINT ["/entrypoint.sh"]
