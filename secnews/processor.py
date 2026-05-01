"""Stage 2: Classify articles by severity and send each item to Telegram.

Runs at :05 every hour. Reads {DATA_DIR}/cyber_news_24h.json, classifies
unprocessed items into critical/high/medium/discard, dedups by CVE-ID and
fuzzy title overlap, then sends each item as its own Telegram message
(one item = one channel post). Successfully-sent items are marked
processed individually, so a transient failure on one item only retries
that item next cycle — successful items are not re-sent.
"""

from __future__ import annotations

import json
import random
import re
import sys
import time
from datetime import datetime, timezone

from . import config
from .sender import escape_html, escape_html_attr, send_message

log = config.setup_logging("processor")

# Seconds to sleep between item sends. Telegram allows ~1 msg/sec sustained
# to a single chat; 2s gives plenty of margin and absorbs the occasional
# slow API response.
SEND_DELAY_SECONDS = 2.0

# Severities that post silently (no push notification, no in-app sound).
# Empty by default — every item pings. Add e.g. "medium" here if you ever
# want low-severity items to deliver quietly.
QUIET_SEVERITIES: set[str] = set()


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
#
# We compare every incoming article against everything we've already kept
# this cycle and reject it if any of these signals fires:
#
#   1. Same CVE-ID  -> exact dup
#   2. Title Jaccard >= TITLE_JACCARD       (after stop-word + stem)
#   3. Combined (title+desc) Jaccard >= COMBINED_JACCARD
#   4. Lower combined Jaccard (>= SECONDARY_JACCARD) AND >= MIN_SHARED_SPECIFIC
#      shared "specific" tokens (length >= 6, post-stem) — catches stories
#      that share a few rare technical/proper-noun terms even when generic
#      phrasing differs
#
# Override: if both articles carry CVE IDs and they're DIFFERENT, we never
# merge them — that prevents e.g. CVE-2026-42778 and CVE-2026-42779 in
# Apache MINA from being collapsed just because their titles overlap.
#
# Thresholds err aggressive: the user explicitly prefers occasionally
# suppressing a unique-but-similar story over shipping 4 different outlets'
# write-ups of the same incident.

TITLE_JACCARD = 0.30
COMBINED_JACCARD = 0.25
SECONDARY_JACCARD = 0.10
MIN_SHARED_SPECIFIC = 3
SPECIFIC_MIN_LEN = 6

_CVE_FINDALL = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_HTML_TAG = re.compile(r"<[^>]+>")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")

# Common English words plus a few headline-stuffer words ("two", "new",
# "us", "uk") that carry no topic information.
_STOPWORDS: frozenset[str] = frozenset({
    "the", "and", "for", "are", "was", "were", "with", "from", "that", "this",
    "these", "those", "have", "has", "had", "having", "been", "being", "but",
    "not", "you", "your", "they", "their", "them", "his", "her", "its", "our",
    "him", "she", "who", "what", "when", "where", "why", "how", "all", "any",
    "both", "each", "few", "more", "most", "other", "some", "such", "only",
    "own", "same", "than", "too", "very", "can", "will", "just", "now", "also",
    "into", "out", "over", "under", "again", "further", "then", "once", "here",
    "there", "off", "above", "below", "during", "before", "after", "between",
    "around", "such", "less", "still", "yet", "while", "though", "although",
    "however", "thus", "hence", "therefore", "because", "since", "until",
    "unless", "if", "say", "said", "says", "make", "made", "use", "used",
    "get", "got", "going", "goes", "see", "seen", "may", "might", "must",
    "should", "would", "could", "shall", "ought", "did", "does", "doing",
    # headline filler — almost meaningless on their own
    "two", "three", "four", "five", "new", "old", "first", "last", "year",
    "years", "day", "days", "week", "month", "us", "uk", "eu", "vs", "via",
    "way", "ways", "back", "next", "today", "tomorrow", "yesterday",
})


def _stem(word: str) -> str:
    """Tiny suffix-strip stemmer. Not Porter-grade but no extra deps."""
    for suffix in ("ies", "ied", "ing", "ed", "es", "s"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 3:
            return word[: -len(suffix)]
    return word


def _tokenize(text: str) -> frozenset[str]:
    """Lowercase, drop HTML, drop punctuation, drop stopwords, simple stem."""
    if not text:
        return frozenset()
    cleaned = _HTML_TAG.sub(" ", text.lower())
    return frozenset(
        _stem(t)
        for t in _NON_ALNUM.split(cleaned)
        if t and len(t) > 2 and t not in _STOPWORDS
    )


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    if inter == 0:
        return 0.0
    return inter / len(a | b)


def dedup_items(items: list[dict]) -> list[dict]:
    seen_cves: set[str] = set()
    sigs: list[dict] = []
    out: list[dict] = []

    for item in items:
        title = item.get("title", "") or ""
        desc = item.get("description", "") or ""
        combined = f"{title} {desc[:600]}"

        cves = {m.upper() for m in _CVE_FINDALL.findall(combined)}
        if cves and any(c in seen_cves for c in cves):
            continue

        title_tokens = _tokenize(title)
        combined_tokens = _tokenize(combined)
        specific = frozenset(t for t in combined_tokens if len(t) >= SPECIFIC_MIN_LEN)

        is_dup = False
        for prev in sigs:
            # Different CVEs → always treat as distinct vulnerabilities.
            if cves and prev["cves"] and not (cves & prev["cves"]):
                continue

            # Signal 1: title tokens overlap heavily.
            t_inter = len(title_tokens & prev["title"])
            if t_inter >= 2:
                t_jac = t_inter / max(len(title_tokens | prev["title"]), 1)
                if t_jac >= TITLE_JACCARD:
                    is_dup = True
                    break

            # Signal 2: title+description tokens overlap.
            c_inter = len(combined_tokens & prev["combined"])
            if c_inter >= 3:
                c_jac = c_inter / max(len(combined_tokens | prev["combined"]), 1)
                if c_jac >= COMBINED_JACCARD:
                    is_dup = True
                    break
                # Signal 3: weaker text overlap rescued by shared rare tokens.
                if (
                    c_jac >= SECONDARY_JACCARD
                    and len(specific & prev["specific"]) >= MIN_SHARED_SPECIFIC
                ):
                    is_dup = True
                    break

        if is_dup:
            continue

        seen_cves |= cves
        sigs.append({
            "cves": cves,
            "title": title_tokens,
            "combined": combined_tokens,
            "specific": specific,
        })
        out.append(item)
    return out


# === MESSAGE FORMATTING (HTML) ===
SEVERITY_ICONS = {
    "critical": "\U0001F534",  # 🔴
    "high": "\U0001F7E0",       # 🟠
    "medium": "\U0001F7E1",     # 🟡
}
DEFAULT_ICON = "\U0001F539"    # 🔹


def _format_item(item: dict) -> str:
    title = escape_html(item.get("title", "").strip())
    summary = item.get("_summary", "")
    source = escape_html(item.get("source", "Unknown"))
    url = escape_html_attr(item.get("url", ""))
    icon = SEVERITY_ICONS.get(item.get("_severity"), DEFAULT_ICON)

    lines = [f"{icon} <b>{title}</b>"]
    if summary:
        lines.append(f"<blockquote>{escape_html(summary)}</blockquote>")
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
        item["_severity"] = sev
        if sev == "critical":
            critical.append(item)
        elif sev == "high":
            high.append(item)
        elif sev == "medium":
            medium.append(item)

    # Order by severity (critical → high → medium), then dedup once across
    # the union so a story landing in two buckets only ships once.
    items = dedup_items(critical + high + medium)
    total = len(items)

    log.info("After classification: %d critical, %d high, %d medium (%d total post-dedup).",
             len(critical), len(high), len(medium), total)

    if total == 0:
        send_funny()
        _mark_processed_indices(data, [idx for idx, _ in unprocessed])
        return 0

    sent_indices, failed = _send_items_individually(items, unprocessed)

    log.info("Sent %d/%d items individually (%d failed).",
             len(sent_indices), total, failed)
    _mark_processed_indices(data, sent_indices)
    return 0 if failed == 0 else 4


def _send_items_individually(
    items: list[dict],
    unprocessed: list[tuple[int, dict]],
) -> tuple[list[int], int]:
    """Send each item as its own Telegram message.

    Returns (indices_of_successfully_sent_items_in_data, failure_count).
    Items not in the returned list keep `processed: false` and will be
    retried next cycle.
    """
    # Map url → index in `data` so we can mark only successful sends.
    url_to_idx = {item.get("url", ""): idx for idx, item in unprocessed}

    sent_indices: list[int] = []
    failed = 0
    total = len(items)

    for i, item in enumerate(items, start=1):
        sev = item.get("_severity", "medium")
        quiet = sev in QUIET_SEVERITIES
        title_preview = item.get("title", "")[:70]
        body = _format_item(item)
        log.info("[%d/%d] %s | severity=%s quiet=%s",
                 i, total, title_preview, sev, quiet)

        try:
            results = send_message(
                body,
                parse_mode="HTML",
                disable_notification=quiet,
            )
            if all(r.get("ok") for r in results):
                idx = url_to_idx.get(item.get("url", ""))
                if idx is not None:
                    sent_indices.append(idx)
            else:
                log.error("[%d/%d] send returned non-ok: %s", i, total, results)
                failed += 1
        except Exception as e:
            log.error("[%d/%d] send raised: %s", i, total, e)
            failed += 1

        if i < total:
            time.sleep(SEND_DELAY_SECONDS)

    return sent_indices, failed


def _mark_processed_indices(data: list[dict], indices: list[int]) -> None:
    if not indices:
        return
    for idx in indices:
        data[idx]["processed"] = True
        data[idx].pop("_summary", None)
        data[idx].pop("_severity", None)
    tmp = config.WINDOW_FILE.with_suffix(config.WINDOW_FILE.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(config.WINDOW_FILE)


if __name__ == "__main__":
    sys.exit(main())
