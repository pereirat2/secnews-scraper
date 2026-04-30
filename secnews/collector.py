"""Stage 1: Collect security news from RSS/Atom/JSON feeds.

Runs at :00 every hour. Writes deduplicated, time-windowed articles to
{DATA_DIR}/cyber_news_24h.json for the processor to consume at :05.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from html import unescape
from pathlib import Path
from urllib.parse import urlparse

import feedparser
import requests

from . import config
from .sources import (
    AGGREGATOR_SOURCES,
    HTML_SCRAPE_SOURCES,
    KEYWORD_INCLUDE_PATTERNS,
    SOURCES,
)

log = config.setup_logging("collector")

_KEYWORD_RE = [re.compile(p, re.IGNORECASE) for p in KEYWORD_INCLUDE_PATTERNS]


def normalize_url(url: str) -> str:
    url = url.strip().lower()
    parsed = urlparse(url)
    if parsed.netloc.startswith("www."):
        parsed = parsed._replace(netloc=parsed.netloc[4:])
        url = parsed.geturl()
    if url.endswith("/") and parsed.path != "/":
        url = url.rstrip("/")
    return url


def _atomic_write_json(path: Path, data) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.replace(tmp, path)


def load_dedup() -> tuple[dict, str]:
    if not config.DEDUP_FILE.exists():
        return {}, datetime.now(timezone.utc).isoformat()
    try:
        data = json.loads(config.DEDUP_FILE.read_text())
    except (json.JSONDecodeError, OSError) as e:
        log.warning("Could not read dedup file (%s) — starting fresh.", e)
        return {}, datetime.now(timezone.utc).isoformat()
    seen = data.get("seen", {})
    if isinstance(seen, list):
        seen = {}
    return seen, data.get("timestamp", datetime.now(timezone.utc).isoformat())


def save_dedup(seen: dict, ts: str) -> None:
    _atomic_write_json(config.DEDUP_FILE, {"seen": seen, "timestamp": ts})


def purge_old_dedup(seen: dict) -> None:
    now = datetime.now(timezone.utc)
    to_del: list[str] = []
    for url, ts in seen.items():
        try:
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if (now - dt).total_seconds() > config.DEDUP_TTL_SECONDS:
                to_del.append(url)
        except (ValueError, TypeError):
            to_del.append(url)
    for url in to_del:
        del seen[url]
    if to_del:
        log.info("Purged %d expired dedup entries.", len(to_del))


def fetch_feed(source: str, url: str, headers: dict | None):
    h = dict(headers or {})
    h.setdefault("User-Agent", "Mozilla/5.0 (compatible; SecurityNewsCollector/1.0)")
    for attempt in range(1, config.MAX_RETRIES + 2):
        try:
            resp = requests.get(url, timeout=config.HTTP_TIMEOUT, headers=h)
            resp.raise_for_status()
            if ".json" in url:
                return resp.json()
            feed = feedparser.parse(resp.content)
            if feed.bozo and not feed.entries:
                log.warning("%s: empty/bozo feed.", source)
                return []
            return feed.entries
        except Exception as e:
            log.warning("%s attempt %d failed: %s", source, attempt, e)
            if attempt <= config.MAX_RETRIES:
                time.sleep(config.RETRY_DELAY)
    log.error("%s: giving up after %d attempts.", source, config.MAX_RETRIES + 1)
    return None


def _clean_description(raw: str) -> str:
    """Decode HTML entities and strip tags down to plain text, capped at 500 chars."""
    if not raw:
        return ""
    text = re.sub(r"<[^>]+>", "", raw)
    text = unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:500]


def parse_entry(entry, source: str) -> dict | None:
    title = (entry.get("title") or "").strip()
    desc = entry.get("description") or entry.get("summary") or ""
    desc = _clean_description(desc)

    link = ""
    if "link" in entry:
        link = entry.link
    elif entry.get("links"):
        for l in entry.links:
            if l.get("rel") == "alternate":
                link = l.get("href", "")
                break
        if not link:
            link = entry.links[0].get("href", "")
    if not link:
        return None

    published = entry.get("published") or entry.get("updated") or ""
    pub_dt = None
    try:
        if getattr(entry, "published_parsed", None):
            pub_dt = datetime.fromtimestamp(time.mktime(entry.published_parsed), tz=timezone.utc)
        elif published:
            pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except Exception:
        pub_dt = None
    if not pub_dt:
        return None

    return {
        "title": title,
        "url": link,
        "source": source,
        "published_at": pub_dt.isoformat(),
        "description": desc,
    }


def parse_json_entries(data, source: str) -> list[dict]:
    out: list[dict] = []
    if isinstance(data, list):
        for item in data:
            cve = item.get("cveID", "")
            vn = item.get("vulnerabilityName", "")
            title = f"{cve}: {vn}" if cve and vn else (vn or cve or "")
            if not title:
                continue
            try:
                date_added = item.get("dateAdded", "")
                pub_dt = datetime.fromisoformat(date_added).replace(tzinfo=timezone.utc) if date_added else datetime.now(timezone.utc)
            except Exception:
                pub_dt = datetime.now(timezone.utc)
            out.append({
                "title": title,
                "url": item.get("url", ""),
                "source": source,
                "published_at": pub_dt.isoformat(),
                "description": (item.get("shortDescription") or "")[:500],
            })
        return out
    if isinstance(data, dict) and "data" in data:
        for child in data["data"].get("children", []):
            d = child.get("data", {})
            title = (d.get("title") or "").strip()
            if not title:
                continue
            ts = d.get("created_utc", 0)
            pub_dt = datetime.fromtimestamp(ts, tz=timezone.utc) if ts else datetime.now(timezone.utc)
            out.append({
                "title": title,
                "url": d.get("url", ""),
                "source": source,
                "published_at": pub_dt.isoformat(),
                "description": _clean_description(d.get("selftext") or ""),
            })
    return out


def scrape_full_disclosure(source: str, url: str) -> list[dict]:
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        articles: list[dict] = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for m in re.finditer(
            r'<a\s+href="(https://seclists\.org/fulldisclosure/[^"]+)"[^>]*>([^<]+)</a>',
            resp.text,
            re.IGNORECASE,
        ):
            title = m.group(2).strip()
            if not title:
                continue
            articles.append({
                "title": title,
                "url": m.group(1),
                "source": source,
                "published_at": now_iso,
                "description": "",
            })
        return articles
    except Exception as e:
        log.error("FullDisclosure scrape error: %s", e)
        return []


def matches_security_keywords(text: str) -> bool:
    return any(p.search(text) for p in _KEYWORD_RE)


def is_title_duplicate(title: str, existing: list[dict]) -> bool:
    tn = (title or "").strip().lower()
    if not tn:
        return False
    for a in existing:
        et = a.get("title", "").strip().lower()
        if et == tn:
            return True
        if len(tn) > 20 and len(et) > 20 and SequenceMatcher(None, tn, et).ratio() > 0.9:
            return True
    return False


def load_window() -> list[dict]:
    if not config.WINDOW_FILE.exists():
        return []
    try:
        return json.loads(config.WINDOW_FILE.read_text())
    except Exception:
        return []


def save_window(articles: list[dict]) -> None:
    _atomic_write_json(config.WINDOW_FILE, articles)


def prune_window(articles: list[dict]) -> list[dict]:
    if not articles:
        return []
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=config.WINDOW_HOURS)
    out: list[dict] = []
    for a in articles:
        try:
            collected_dt = datetime.fromisoformat(a.get("collected_at", ""))
            if collected_dt.tzinfo is None:
                collected_dt = collected_dt.replace(tzinfo=timezone.utc)
            if collected_dt > cutoff:
                out.append(a)
        except Exception:
            continue
    return out


def collect() -> tuple[int, int, int, int]:
    """Returns (new_articles, total_window, sources_ok, sources_failed)."""
    config.ensure_dirs()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=config.WINDOW_HOURS)

    seen, _ = load_dedup()
    log.info("Loaded %d dedup entries.", len(seen))
    purge_old_dedup(seen)

    new_articles: list[dict] = []
    new_dedup_pairs: list[tuple[str, str]] = []
    sources_ok = 0
    sources_failed = 0

    for source_name, feed_url, is_json, headers in SOURCES:
        log.info("Fetching %s ...", source_name)

        if source_name in HTML_SCRAPE_SOURCES:
            entries = scrape_full_disclosure(source_name, feed_url)
            if not entries:
                sources_failed += 1
                continue
            sources_ok += 1
            for p in entries:
                _maybe_add(p, seen, new_articles, new_dedup_pairs, now, source_name)
            continue

        raw = fetch_feed(source_name, feed_url, headers)
        if raw is None:
            sources_failed += 1
            continue
        sources_ok += 1
        if not raw:
            continue

        if is_json or ".json" in feed_url:
            parsed = parse_json_entries(raw, source_name)
        else:
            parsed = []
            for e in raw:
                p = parse_entry(e, source_name)
                if p:
                    parsed.append(p)

        for p in parsed:
            try:
                pub_dt = datetime.fromisoformat(p["published_at"])
                if pub_dt.tzinfo is None:
                    pub_dt = pub_dt.replace(tzinfo=timezone.utc)
                if pub_dt < cutoff:
                    continue
            except Exception:
                continue
            _maybe_add(p, seen, new_articles, new_dedup_pairs, now, source_name)

    log.info("Collected %d new articles (%d sources ok, %d failed).",
             len(new_articles), sources_ok, sources_failed)

    for url, ts in new_dedup_pairs:
        seen[url] = ts
    save_dedup(seen, now.isoformat())

    window = prune_window(load_window())
    window.extend(new_articles)
    window = prune_window(window)
    save_window(window)

    return len(new_articles), len(window), sources_ok, sources_failed


def _maybe_add(p: dict, seen: dict, new_articles: list[dict],
               new_dedup_pairs: list[tuple[str, str]], now: datetime,
               source_name: str) -> None:
    if not p.get("url"):
        return
    nu = normalize_url(p["url"])
    if nu in seen:
        return

    if source_name in AGGREGATOR_SOURCES:
        haystack = f"{p.get('title', '')} {p.get('description', '')}"
        if not matches_security_keywords(haystack):
            return

    if is_title_duplicate(p.get("title", ""), new_articles):
        return

    p["collected_at"] = now.isoformat()
    new_articles.append(p)
    new_dedup_pairs.append((nu, now.isoformat()))


def main() -> int:
    try:
        new, total, ok, failed = collect()
    except Exception as e:
        log.exception("Fatal collector error: %s", e)
        return 2

    log.info("Done: %d new, %d in 24h window.", new, total)

    if ok == 0:
        log.error("No sources succeeded — failing run.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
