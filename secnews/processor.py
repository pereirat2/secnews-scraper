"""Stage 2: Classify articles by severity and send digest to Telegram.

Runs at :05 every hour. Reads {DATA_DIR}/cyber_news_24h.json, classifies
unprocessed items into critical/high/medium/discard, dedups by CVE-ID and
fuzzy title overlap, formats an HTML message, and sends via secnews.sender.
"""

from __future__ import annotations

import json
import random
import re
import sys
from datetime import datetime, timezone

from . import config
from .sender import escape_html, escape_html_attr, send_message

log = config.setup_logging("processor")


# === SEVERITY CLASSIFICATION ===
CRITICAL_PATTERNS = [
    r"(?i)(zero.?day|0.?day).*(exploit|wild|active|critical|rce|remote|auth|bypass)",
    r"(?i)active(ly)?\s+(exploit|attack)",
    r"(?i)critical.*(auth.?bypass|rce|remote.?code)",
    r"(?i)(auth.?bypass|rce).*(critical|emergency|all.?versions)",
    r"(?i)emergency.*(patch|update|fix)",
    r"(?i)cisa.*(known.?exploit|exploit.*known).*vulnerab",
    r"(?i)(microsoft|google|apple|cisco|vmware|oracle).*(critical|urgent|emergency).*(patch|update|fix).*cve",
    r"(?i)(actively|already|in the wild).*(exploit|attack)",
    r"(?i)(microsoft|google|apple|cisco|vmware|oracle).*(zero.?day|0.?day).*(rce|remote|auth.?bypass|exploit)",
    r"(?i)(actively).*(zero.?day|0.?day)",
]

HIGH_PATTERNS = [
    r"(?i)(cve-\d{4}-\d+).*\b(rce|remote.?code|command.?inject|critical)\b",
    r"(?i)\b(rce|remote.?code.?execution)\b",
    r"(?i)(apt|nation.?state|dprk|north.?korea|lazarus|bluenoroff|fancy.?bear|sandworm|cozy.?bear)",
    r"(?i)\b(ransomware|wiper|backdoor|trojan|\brat\b|rootkit)\b",
    r"(?i)(poc|proof.?of.?concept|exploit.*(available|release|public))",
    r"(?i)(supply.?chain|npm|pypi|pip |gem |cargo).*(attack|malware|compromis|backdoor|trojan)",
    r"(?i)million.*(record|user|account|repositor).*(exposed|breach|leak|compromis)",
    r"(?i)(new|novel|emerging).*(malware|ransomware|threat)",
    r"(?i)(campaign|wave|attack).*(target|victim)",
    r"(?i)(privilege.?escalat|local.?exploit|\blpe\b|bytes.?to.?root|root.*(linux|windows|all))",
    r"(?i)(compromis|hijack|takeover).*(package|plugin|extension|library|module)",
    r"(?i)cve-\d{4}-\d+",
    r"(?i)cisa.*(alert|advisory|catalog|kev)",
    r"(?i)(aws|azure|gcp|cloud).*(vulnerab|exposed|misconfig|breach|leak)",
]

MEDIUM_PATTERNS = [
    r"(?i)(vulnerabilit|flaw|bug|patch|advisory|update|fix).*(disclos|discover|release|publish)",
    r"(?i)(research|study|report|analysis).*(find|reveal|discover|show|uncover)",
    r"(?i)(phishing|scam|fraud|credential|data.?theft|identity.?theft)",
    r"(?i)(security|cyber).*(update|patch|fix|advisory|warning|alert|notice)",
    r"(?i)(breach|leak|exposed|stolen|compromis).*(data|record|account|user|password)",
    r"(?i)(malware|spyware|adware|keylogger).*(found|detect|discover|spread)",
    r"(?i)(hacker|attacker|threat.?actor).*(target|exploit|compromis|breach)",
    r"(?i)(password|credential|token|key|secret).*(leak|stolen|exposed|compromis)",
    r"(?i)(honeypot|threat.?intel|\bioc\b|indicator)",
]

DISCARD_PATTERNS = [
    r"(?i)^(the )?abstraction",
    r"(?i)(cherry.?blossom|lisp|haskell|consciousness|philosophy|mathematics|infinity)",
    r"(?i)(opinion|editorial|podcast|interview|call.?for.?paper)",
    r"(?i)(high.?speed.?rail|pentagon.?spend|drone.?spend|military.?budget)",
    r"(?i)(alphabet|earnings|quarter.?results|ipo|stock.?price)",
    r"(?i)(cursor.?game|traffic.?map|opentraffic)",
    r"(?i)(age.?verif|child.?safety|censorship|privacy.?policy)",
    r"(?i)(is.?hiring|we.?are.?hiring|job.?opening|founding.?engineer|join.?our.?team)",
    r"(?i)(programming.?language|functional.?program|monad|type.?system|compiler)",
    r"(?i)(crude.?oil|barrel|commodit|stock.?market|crypto.?price|bitcoin.?price)",
    r"(?i)(biology|chemistry|physics|astronomy|space.?mission|rocket.?launch)",
    r"(?i)(died|obituary|passes.?away|craig.?venter|celebrity)",
    r"(?i)(air.?taxi|electric.?vehicle|joby|uber.?air|evtol)",
    r"(?i)(book|novel|tutorial|monad.?tutorial|conference(?!.*security))",
    r"(?i)^(zulip|emacs|vim|neovim|helix|nvim)\s",
]

_DISCARD_RE = [re.compile(p) for p in DISCARD_PATTERNS]
_CRITICAL_RE = [re.compile(p) for p in CRITICAL_PATTERNS]
_HIGH_RE = [re.compile(p) for p in HIGH_PATTERNS]
_MEDIUM_RE = [re.compile(p) for p in MEDIUM_PATTERNS]


def classify(title: str, description: str) -> str:
    text = f"{title} {description}"
    if any(r.search(text) for r in _DISCARD_RE):
        return "discard"
    if any(r.search(text) for r in _CRITICAL_RE):
        return "critical"
    if any(r.search(text) for r in _HIGH_RE):
        return "high"
    if any(r.search(text) for r in _MEDIUM_RE):
        return "medium"
    return "discard"


# === SUMMARY EXTRACTION ===
_CVE_RE = re.compile(r"cve-\d{4}-\d+", re.IGNORECASE)
_COUNT_RE = re.compile(
    r"\b\d+(\.\d+)?\s*(million|billion|thousand|k|records|users|accounts|devices|systems)\b",
    re.IGNORECASE,
)
_VERB_RE = re.compile(
    r"\b(allows|bypasses|executes|leverages|exposes|grants|enables|discloses)\b",
    re.IGNORECASE,
)


def extract_summary(title: str, description: str, max_words: int = 25) -> str:
    if not description or len(description) < 20:
        return ""
    sentences = re.split(r"(?<=[.!?])\s+", description)

    def score(s: str) -> int:
        v = 0
        if _CVE_RE.search(s):
            v += 3
        if _COUNT_RE.search(s):
            v += 2
        if _VERB_RE.search(s):
            v += 2
        return v

    scored = [(score(s), s) for s in sentences[:4] if len(s.split()) >= 5]
    if scored:
        scored.sort(key=lambda x: x[0], reverse=True)
        if scored[0][0] > 1:
            return _truncate_words(scored[0][1], max_words)

    title_l = title.lower().strip().rstrip(".")
    for sent in sentences[:3]:
        sl = sent.lower().strip().rstrip(".")
        if sl == title_l or len(sent.split()) < 5:
            continue
        return _truncate_words(sent, max_words)

    if sentences and len(sentences[0]) > 20:
        return _truncate_words(sentences[0], max_words)
    return ""


def _truncate_words(sent: str, max_words: int) -> str:
    words = sent.split()[:max_words]
    out = " ".join(words)
    if len(words) == max_words and not out.endswith("."):
        out += "..."
    return out


# === DEDUPLICATION ===
def dedup_items(items: list[dict]) -> list[dict]:
    seen_cves: set[str] = set()
    seen_titles: list[str] = []
    out: list[dict] = []

    for item in items:
        title = item.get("title", "")
        desc = item.get("description", "")
        combined = f"{title} {desc}"
        cves = {m.upper() for m in re.findall(r"CVE-\d{4}-\d+", combined, re.IGNORECASE)}
        if any(c in seen_cves for c in cves):
            continue
        seen_cves |= cves

        tl = title.lower()
        words = tl.split()
        if len(words) < 4:
            if any(tl == s for s in seen_titles):
                continue
        else:
            wa = set(words)
            duplicate = False
            for s in seen_titles:
                wb = set(s.split())
                overlap = len(wa & wb) / max(len(wa | wb), 1)
                if overlap > 0.6:
                    duplicate = True
                    break
            if duplicate:
                continue

        seen_titles.append(tl)
        out.append(item)
    return out


# === MESSAGE FORMATTING (HTML) ===
ITEM_DIVIDER = "-----"


def format_message(items: list[dict]) -> str:
    """Render the digest. Items should already be deduped and ordered.

    The divider is glued to the END of each non-last item (with a blank line
    above it). This keeps `divider + next item` from being orphaned across
    Telegram chunk boundaries — the chunker splits on blank-line paragraph
    breaks, so an item-with-trailing-divider is treated as a single atomic
    block.
    """
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%d %b %Y %H:%M")

    blocks: list[str] = [f"<b>SECURITY DIGEST</b> — {escape_html(date_str)} UTC"]
    last = len(items) - 1
    for i, item in enumerate(items):
        block = _format_item(item)
        if i < last:
            block = f"{block}\n\n{ITEM_DIVIDER}"
        blocks.append(block)
    blocks.append("<i>— Next update in ~60 min</i>")
    return "\n\n".join(blocks)


def _format_item(item: dict) -> str:
    title = escape_html(item.get("title", "").strip())
    summary = item.get("_summary", "")
    source = escape_html(item.get("source", "Unknown"))
    url = escape_html_attr(item.get("url", ""))

    lines = [f"<b>{title}</b>"]
    if summary:
        lines.append("")
        lines.append(f"<b>Summary:</b> {escape_html(summary)}")
    lines.append(f"<b>Source:</b> {source} | <a href=\"{url}\">Read more</a>")
    return "\n".join(lines)


# === FUNNY FILLER ===
FUNNY_MESSAGES = [
    "\U0001F6E1\uFE0F All quiet on the cyber front. Even the hackers are taking a break.",
    "\u2615 No new threats detected. Time for coffee and threat modeling.",
    "\U0001F512 Zero alerts this hour. Either we're secure or the attackers are asleep.",
    "\U0001F3AF Nothing to report. The honeypots are lonely today.",
    "\U0001F319 Quiet hour in cyberspace. Even APTs need sleep.",
    "\u2705 Clean sweep this cycle. Patch your systems while it's calm.",
]


def send_funny() -> None:
    now = datetime.now(timezone.utc)
    hour_key = now.strftime("%Y-%m-%dT%H")
    if config.FUNNY_STATE_FILE.exists():
        last = config.FUNNY_STATE_FILE.read_text().strip()
        if last == hour_key:
            log.info("Funny already sent this hour — skipping.")
            return
    msg = random.choice(FUNNY_MESSAGES)
    try:
        send_message(msg, parse_mode=None)
        config.FUNNY_STATE_FILE.write_text(hour_key)
        log.info("Sent funny filler message.")
    except Exception as e:
        log.error("Failed to send funny: %s", e)


# === MAIN ===
def main() -> int:
    config.ensure_dirs()
    if not config.WINDOW_FILE.exists():
        log.warning("No window file at %s — nothing to process.", config.WINDOW_FILE)
        return 0

    try:
        data = json.loads(config.WINDOW_FILE.read_text())
    except Exception as e:
        log.exception("Could not load window file: %s", e)
        return 2

    unprocessed = [(i, item) for i, item in enumerate(data) if not item.get("processed")]
    log.info("Unprocessed items in window: %d", len(unprocessed))

    if not unprocessed:
        send_funny()
        return 0

    critical: list[dict] = []
    high: list[dict] = []
    medium: list[dict] = []

    for _, item in unprocessed:
        sev = classify(item.get("title", ""), item.get("description", ""))
        if sev == "discard":
            continue
        item["_summary"] = extract_summary(item.get("title", ""), item.get("description", ""))
        if sev == "critical":
            critical.append(item)
        elif sev == "high":
            high.append(item)
        elif sev == "medium":
            medium.append(item)

    # Severity is still used for ordering (critical → high → medium), but no
    # longer surfaced in the digest. Dedup once across the union so we don't
    # emit the same story twice if it landed in two buckets.
    items = dedup_items(critical + high + medium)
    total = len(items)

    log.info("After classification: %d critical, %d high, %d medium (%d total post-dedup).",
             len(critical), len(high), len(medium), total)

    if total == 0:
        send_funny()
        _mark_processed(data, unprocessed)
        return 0

    message = format_message(items)
    log.info("Built digest: %d chars.", len(message))

    try:
        # Split only at item boundaries — the divider is glued between items
        # and never appears inside one, so chunks can never break a single
        # item across two Telegram messages.
        results = send_message(
            message,
            parse_mode="HTML",
            chunk_separator=f"\n\n{ITEM_DIVIDER}\n\n",
        )
    except Exception as e:
        log.exception("Send failed: %s", e)
        return 3

    if all(r.get("ok") for r in results):
        _mark_processed(data, unprocessed)
        log.info("SUCCESS: %d items reported, all marked processed.", total)
        return 0
    log.error("Send returned non-ok: %s", results)
    return 4


def _mark_processed(data: list[dict], unprocessed: list[tuple[int, dict]]) -> None:
    for idx, _ in unprocessed:
        data[idx]["processed"] = True
        data[idx].pop("_summary", None)
    tmp = config.WINDOW_FILE.with_suffix(config.WINDOW_FILE.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(config.WINDOW_FILE)


if __name__ == "__main__":
    sys.exit(main())
