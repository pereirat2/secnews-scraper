"""Telegram sender — HTML parse mode, importable + CLI.

Telegram HTML rules:
  - Only <b>, <i>, <u>, <s>, <code>, <pre>, <a href=...>, <tg-spoiler> allowed.
  - Inside text: escape & < >  (only those three).
  - Inside href attribute: also escape ".
  - Hard limit 4096 chars per message.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Iterable

import requests

from . import config

log = logging.getLogger(__name__)

API_BASE = "https://api.telegram.org"
MAX_LEN = 4000
MAX_RETRIES = 3
RETRY_BACKOFF = 2.0


def escape_html(text: str) -> str:
    """Escape user-controlled text for safe inclusion in Telegram HTML."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def escape_html_attr(text: str) -> str:
    """Escape value for an href= attribute (text rules + double quote)."""
    return escape_html(text).replace('"', "&quot;")


def _split_for_telegram(message: str, limit: int = MAX_LEN) -> list[str]:
    """Split a long message preserving paragraph boundaries (\\n\\n)."""
    if len(message) <= limit:
        return [message]
    paragraphs = message.split("\n\n")
    chunks: list[str] = []
    current = ""
    for para in paragraphs:
        candidate = current + ("\n\n" if current else "") + para
        if len(candidate) > limit and current:
            chunks.append(current)
            current = para
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks


def _post_chunk(text: str, parse_mode: str | None) -> dict:
    url = f"{API_BASE}/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": config.TELEGRAM_CHAT_ID,
        "text": text,
        "disable_web_page_preview": True,
    }
    if parse_mode:
        payload["parse_mode"] = parse_mode

    last_exc: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(url, json=payload, timeout=20)
            data = resp.json()
            if data.get("ok"):
                return data
            desc = str(data.get("description", "")).lower()
            if "parse" in desc and parse_mode:
                log.warning("Telegram rejected parse_mode=%s: %s — retrying as plain.", parse_mode, desc)
                payload.pop("parse_mode", None)
                resp = requests.post(url, json=payload, timeout=20)
                data = resp.json()
                data["_fallback"] = "sent without formatting"
                return data
            log.error("Telegram error (attempt %d): %s", attempt, data)
            last_exc = RuntimeError(f"telegram error: {data}")
        except requests.RequestException as e:
            log.warning("Telegram network error (attempt %d): %s", attempt, e)
            last_exc = e
        if attempt < MAX_RETRIES:
            time.sleep(RETRY_BACKOFF * attempt)
    raise RuntimeError(f"Telegram send failed after {MAX_RETRIES} attempts: {last_exc}")


def send_message(text: str, parse_mode: str | None = "HTML") -> list[dict]:
    """Send a message to the configured chat, splitting if necessary.
    Returns the list of API responses (one per chunk).
    """
    if not text or not text.strip():
        raise ValueError("send_message: empty message")
    chunks = _split_for_telegram(text)
    results: list[dict] = []
    for i, chunk in enumerate(chunks, start=1):
        log.debug("Sending chunk %d/%d (%d chars)", i, len(chunks), len(chunk))
        results.append(_post_chunk(chunk, parse_mode))
    return results


def _cli(argv: Iterable[str]) -> int:
    args = list(argv)
    parse_mode: str | None = "HTML"

    if "--plain" in args:
        parse_mode = None
        args.remove("--plain")
    if "--markdown" in args:
        parse_mode = "Markdown"
        args.remove("--markdown")
    if "--html" in args:
        parse_mode = "HTML"
        args.remove("--html")

    message: str | None = None
    if "--file" in args:
        idx = args.index("--file")
        path = args[idx + 1]
        with open(path) as f:
            message = f.read()
    elif args:
        message = args[0]
    else:
        message = sys.stdin.read()

    if not message or not message.strip():
        print("Error: No message provided. Use --file <path>, pass as arg, or pipe via stdin.", file=sys.stderr)
        return 1

    config.setup_logging("sender")
    results = send_message(message, parse_mode=parse_mode)
    for r in results:
        print(json.dumps(r))
    return 0 if all(r.get("ok") for r in results) else 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
