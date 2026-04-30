#!/usr/bin/env bash
# One-shot installer for Kali / Debian. Run as root.
# Idempotent: safe to re-run.

set -euo pipefail

PROJECT_ROOT="${SECNEWS_HOME:-/opt/secnews}"
DATA_DIR="${SECNEWS_DATA_DIR:-/var/lib/secnews}"
LOG_DIR="${SECNEWS_LOG_DIR:-/var/log/secnews}"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Must be run as root." >&2
    exit 1
fi

echo "[*] Installing OS deps..."
apt-get update -y
apt-get install -y --no-install-recommends python3 python3-venv python3-pip util-linux logrotate

echo "[*] Creating dirs..."
mkdir -p "$DATA_DIR" "$LOG_DIR"
chmod 750 "$DATA_DIR" "$LOG_DIR"

echo "[*] Building Python venv at $PROJECT_ROOT/.venv ..."
python3 -m venv "$PROJECT_ROOT/.venv"
"$PROJECT_ROOT/.venv/bin/pip" install --upgrade pip
"$PROJECT_ROOT/.venv/bin/pip" install -r "$PROJECT_ROOT/requirements.txt"

echo "[*] Installing scripts..."
chmod +x "$PROJECT_ROOT/scripts/run_collector.sh" "$PROJECT_ROOT/scripts/run_processor.sh"

echo "[*] Installing logrotate config..."
install -m 0644 "$PROJECT_ROOT/deploy/logrotate.conf" /etc/logrotate.d/secnews

echo "[*] Installing crontab fragment..."
install -m 0644 "$PROJECT_ROOT/deploy/secnews.cron" /etc/cron.d/secnews
chown root:root /etc/cron.d/secnews

if [[ ! -f "$PROJECT_ROOT/.env" ]]; then
    echo
    echo "[!] No .env at $PROJECT_ROOT/.env — copy .env.example and fill in values:"
    echo "    cp $PROJECT_ROOT/.env.example $PROJECT_ROOT/.env"
    echo "    chmod 600 $PROJECT_ROOT/.env"
    echo "    \$EDITOR $PROJECT_ROOT/.env"
fi

echo
echo "[+] Install complete."
echo "    Smoke test:"
echo "      $PROJECT_ROOT/.venv/bin/python -m secnews.collector"
echo "      $PROJECT_ROOT/.venv/bin/python -m secnews.processor"
echo "    Logs: $LOG_DIR/{collector,processor}.log"
