# secnews-scraper

A zero-LLM cybersecurity news pipeline. Pulls ~30 RSS/Atom/JSON feeds, deduplicates, filters noise via severity classification, and posts each story as an individual Telegram message — one news item, one channel post. Runs as two cron jobs on Linux. No external services beyond the feeds and the Telegram Bot API.

```
   :00 UTC ───► collector ──► /var/lib/secnews/cyber_news_24h.json
                                              │
   :05 UTC ───► processor ──► classify ──► dedup ──► one Telegram message per item
```

## Features

- 30+ feeds: vendor blogs (Google, Mozilla, Mandiant, Unit 42, Talos…), news sites (BleepingComputer, KrebsOnSecurity, The Register, Dark Reading…), researcher Mastodon (Troy Hunt, Will Dormann), CISA KEV, Exploit-DB, and more.
- 48h URL dedup + fuzzy title match (catches the same CVE story across multiple outlets).
- Aggregator sources (HN, Full Disclosure) are filtered against a security keyword list.
- Severity classification (`CRITICAL` / `HIGH` / `MEDIUM` / `DISCARD`) used to filter noise, order items, pick a per-item color icon (🔴/🟠/🟡), and decide whether the post pings subscribers.
- One Telegram message per news item — each story is its own post, scrollable, reactable, forwardable. Items are sent in severity order with a 2-second pacing delay (well within Telegram's per-chat rate limits).
- Quiet delivery for medium-severity items (`disable_notification=true`) — subscribers only get pinged for critical and high.
- Granular retry semantics — items are marked `processed` only on successful send, so a transient failure on one item retries just that item next cycle.
- Item layout: severity icon + bold title + indented summary blockquote + linked source. HTML formatting with parse-failure fallback to plain text.
- Atomic JSON writes, retry/backoff on HTTP, `flock`-protected cron, log rotation.
- Idle-hour "funny filler" message, throttled to once per hour.

### Item format

Each news item is sent as **its own Telegram message**, rendered as:

- A **severity icon** (🔴 critical, 🟠 high, 🟡 medium) immediately before the title — your eye latches onto this at the start of every item.
- A **bold title** (the primary anchor).
- An optional **blockquote summary** — Telegram renders this with a left vertical bar and indent.
- A **bold `Source:` line** with a clickable `Read more` hyperlink to the original article.

```
🔴 GitHub fixes RCE flaw that gave access to millions of private repos
▎ In early March, GitHub patched a critical RCE vulnerability (CVE-2026-3854) that could have allowed attackers to access millions of private repositories.
Source: BleepingComputer | Read more
```

The summary blockquote is omitted when the source feed doesn't provide one. Items are sent in severity order (critical → high → medium), one message every ~2 seconds, until all items for the cycle have been delivered.

### Notification behavior

| Severity | Push notification | Reason |
|----------|------------------:|--------|
| `critical` | yes | Actively-exploited / emergency — should ping. |
| `high`     | yes | CVEs, RCE, ransomware, APTs — usually ping-worthy. |
| `medium`   | no  | Sent silently (`disable_notification=true`) so the channel can carry volume without flooding subscribers with pings. |

This is set by `QUIET_SEVERITIES` in `secnews/processor.py`; tweak it to your taste.

### Delivery & retry semantics

- Items are sent **one at a time** with `SEND_DELAY_SECONDS = 2.0` between sends. With ~30 items per cycle that's ~1 minute of pacing — well under Telegram's per-chat rate limit.
- An item is marked `processed: true` in the window file **only after** Telegram returns `ok: true` for that specific item.
- If a single item's send fails (network glitch, 429 rate-limited, transient API error), the other items in the same cycle still go through. The failed item stays `processed: false` and is retried on the next hour's cron run.
- The processor exits non-zero (code `4`) when any item failed, so cron logs surface the partial failure even when the overall run was mostly successful.

## Project layout

```
secnews-scraper/
├── secnews/                # Python package
│   ├── config.py           # env loader + logging
│   ├── sources.py          # feed registry + keyword include list
│   ├── collector.py        # stage 1: fetch + dedup + window
│   ├── processor.py        # stage 2: classify + format + send
│   └── sender.py           # Telegram client (importable + CLI)
├── scripts/
│   ├── install.sh          # one-shot installer (run as root on Kali/Debian)
│   ├── run_collector.sh    # cron wrapper for stage 1
│   └── run_processor.sh    # cron wrapper for stage 2
├── deploy/
│   ├── secnews.cron        # /etc/cron.d/secnews
│   └── logrotate.conf      # /etc/logrotate.d/secnews
├── requirements.txt
├── .env.example
└── README.md
```

## Quick install (Linux, root)

```bash
git clone git@github.com:pereirat2/secnews-scraper.git /opt/secnews
cd /opt/secnews
cp .env.example .env
chmod 600 .env
$EDITOR .env                 # set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID

bash scripts/install.sh
```
## Quick Update with Alias (Linux, root)
```bash
!This is non destructive for your news data!
From Dev machine -> Server
Add to your ~/.bashrc or ~/.zshrc:

alias secnews-update='cd /opt/secnews && git pull && sudo bash scripts/install.sh && echo "[+] secnews updated"'

```

`install.sh` will:
- Install OS deps (`python3`, `python3-venv`, `util-linux`, `logrotate`).
- Build a venv at `/opt/secnews/.venv` and install `requirements.txt`.
- Create `/var/lib/secnews/` (state) and `/var/log/secnews/` (logs).
- Drop `/etc/cron.d/secnews` (the two cron lines, both `flock`-wrapped).
- Drop `/etc/logrotate.d/secnews` (daily, 14-day retention, compressed).

## Configuration

All runtime config is via env vars, loaded from `.env` at the project root.

| Variable              | Required | Default                | Purpose                                      |
| --------------------- | -------- | ---------------------- | -------------------------------------------- |
| `TELEGRAM_BOT_TOKEN`  | yes      | —                      | Token from `@BotFather`                      |
| `TELEGRAM_CHAT_ID`    | yes      | —                      | Group/chat ID, negative for groups           |
| `SECNEWS_DATA_DIR`    | no       | `/var/lib/secnews`     | Where state JSONs live                       |
| `SECNEWS_LOG_DIR`     | no       | `/var/log/secnews`     | Where rotating logs are written              |
| `SECNEWS_LOG_LEVEL`   | no       | `INFO`                 | Python `logging` level                       |
| `SECNEWS_HOME`        | no       | `/opt/secnews`         | Used by the wrapper scripts only             |
| `SECNEWS_VENV`        | no       | `$SECNEWS_HOME/.venv`  | Used by the wrapper scripts only             |
| `SECNEWS_ENV_FILE`    | no       | `$SECNEWS_HOME/.env`   | Override `.env` location                     |

### Finding your `TELEGRAM_CHAT_ID`

1. Add the bot to your group.
2. Send any message in the group.
3. Run:

   ```bash
   curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" \
       | jq '.result[].message.chat | {id, title, type}'
   ```

4. Use the `id` (negative for groups, positive for DMs).

## Smoke test

After editing `.env`:

```bash
/opt/secnews/.venv/bin/python -m secnews.collector
/opt/secnews/.venv/bin/python -m secnews.processor
```

You can also send an arbitrary message to verify Telegram delivery:

```bash
echo '<b>secnews</b> is online.' | /opt/secnews/.venv/bin/python -m secnews.sender
```

`sender` flags: `--html` (default), `--markdown`, `--plain`, `--file <path>`.

## Cron behavior

The two jobs run hourly:

```cron
0 * * * * root /usr/bin/flock -n /run/secnews-collector.lock /opt/secnews/scripts/run_collector.sh >> /var/log/secnews/collector.log 2>&1
5 * * * * root /usr/bin/flock -n /run/secnews-processor.lock /opt/secnews/scripts/run_processor.sh >> /var/log/secnews/processor.log 2>&1
```

`flock -n` exits silently if the previous run is still in flight — there is no risk of overlapping executions corrupting state.

## Logs

```bash
tail -f /var/log/secnews/collector.log
tail -f /var/log/secnews/processor.log
```

Logs rotate daily, keeping 14 days compressed.

## Adding/removing feeds

Edit `secnews/sources.py`. Each entry is `(name, url, is_json_api, extra_headers)`.

- Add the source name to `AGGREGATOR_SOURCES` if it's noisy/general (HN, FullDisclosure) — this enables keyword filtering against `KEYWORD_INCLUDE_PATTERNS`.
- Add to `HTML_SCRAPE_SOURCES` for sources that need plain-HTML scraping (currently only Full Disclosure).

## Tuning severity classification

Severity is computed internally and used for three things:

1. **Filtering** — anything classified `discard` (or matching no pattern at all) never reaches Telegram.
2. **Ordering** — items appear in the digest most-severe first (`critical → high → medium`).
3. **Per-item icon** — the leading 🔴/🟠/🟡 emoji on each item's title.

Rules live in `secnews/processor.py` as four pattern lists:

- `DISCARD_PATTERNS` — drops the item entirely (matched first).
- `CRITICAL_PATTERNS` — actively-exploited, emergency, in-the-wild, etc.
- `HIGH_PATTERNS` — CVEs, RCE, ransomware, APTs, supply chain.
- `MEDIUM_PATTERNS` — generic vulnerabilities, breaches, phishing.

Anything not matching any list defaults to `discard`.

## Operational notes

- The first run after install will deliver up to 24h of articles individually, paced 2 seconds apart. Expect a noisy first cycle (potentially dozens of posts). If you want to start clean, replace the window with `[]`:
  ```bash
  sudo bash -c 'echo "[]" > /var/lib/secnews/cyber_news_24h.json'
  ```
- The dedup cache (`cyber_news_dedup.json`) persists across runs and self-purges entries older than 48h.
- Per-item granular retry: a Telegram failure on one item leaves only that item as `processed: false`; siblings that succeeded are not re-sent next cycle.
- If you want all items to ping (no quiet medium), edit `QUIET_SEVERITIES` in `secnews/processor.py`. To slow down delivery (e.g., spread items more), bump `SEND_DELAY_SECONDS`.

## Security

- `.env` is gitignored. Never commit it.
- `chmod 600 .env`. The bot token grants full control of the bot.
- If the token is ever leaked, revoke it immediately via `@BotFather` and rotate.
- Cron runs as `root`. Reduce to a service user if you prefer; both directories should then be `chown`ed accordingly.

## License

Personal project. No license — all rights reserved.
