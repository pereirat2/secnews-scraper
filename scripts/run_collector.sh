#!/usr/bin/env bash
# Cron entrypoint for the collector. flock is applied in the crontab line.
set -euo pipefail

PROJECT_ROOT="${SECNEWS_HOME:-/opt/secnews}"
VENV="${SECNEWS_VENV:-$PROJECT_ROOT/.venv}"

cd "$PROJECT_ROOT"
exec "$VENV/bin/python" -m secnews.collector
