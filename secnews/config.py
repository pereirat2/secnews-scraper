"""Configuration loader.

All runtime configuration comes from environment variables. A `.env` file at
the project root (or pointed to by SECNEWS_ENV_FILE) is auto-loaded if present.
No external dependencies — minimal manual loader.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path


def _load_env_file(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_FILE = Path(os.environ.get("SECNEWS_ENV_FILE", _PROJECT_ROOT / ".env"))
_load_env_file(_ENV_FILE)


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable: {name}. "
            f"Set it in {_ENV_FILE} or your shell."
        )
    return value


TELEGRAM_BOT_TOKEN: str = _required("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID: int = int(_required("TELEGRAM_CHAT_ID"))

DATA_DIR = Path(os.environ.get("SECNEWS_DATA_DIR", "/var/lib/secnews"))
LOG_DIR = Path(os.environ.get("SECNEWS_LOG_DIR", "/var/log/secnews"))
LOG_LEVEL = os.environ.get("SECNEWS_LOG_LEVEL", "INFO").upper()

DEDUP_FILE = DATA_DIR / "cyber_news_dedup.json"
WINDOW_FILE = DATA_DIR / "cyber_news_24h.json"
FUNNY_STATE_FILE = DATA_DIR / "last_funny_sent_at.txt"

DEDUP_TTL_SECONDS = 48 * 3600
WINDOW_HOURS = 24
HTTP_TIMEOUT = 20
MAX_RETRIES = 2
RETRY_DELAY = 5


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def setup_logging(component: str) -> logging.Logger:
    """Configure a logger writing to both stderr and {LOG_DIR}/{component}.log."""
    ensure_dirs()
    logger = logging.getLogger("secnews")
    if logger.handlers:
        return logger

    logger.setLevel(LOG_LEVEL)
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s [%(name)s.%(module)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    logger.addHandler(stream)

    log_path = LOG_DIR / f"{component}.log"
    try:
        fh = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=5 * 1024 * 1024, backupCount=5
        )
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except (PermissionError, FileNotFoundError) as e:
        logger.warning("Could not open log file %s: %s", log_path, e)

    return logger
