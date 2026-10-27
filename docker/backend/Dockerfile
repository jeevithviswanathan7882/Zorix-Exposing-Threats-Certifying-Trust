# STAGE 1 - Base
FROM python:3.11-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y \
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
ENV SEMGREP_PATH=/opt/semgrep/bin/semgrep


# STAGE 2 - Development
FROM base AS development

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY backend/ ./backend/
COPY security/ ./security/

COPY docker/backend/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]


# STAGE 3 - Production
FROM base AS production

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY backend/ ./backend/
COPY security/ ./security/

COPY docker/backend/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
