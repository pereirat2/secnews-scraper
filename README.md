# secnews-scraper

A zero-LLM cybersecurity news pipeline. Pulls ~30 RSS/Atom/JSON feeds, deduplicates, classifies by severity, and posts an hourly digest to Telegram. Runs as two cron jobs on Linux. No external services beyond the feeds and the Telegram Bot API.

```
   :00 UTC ───► collector ──► /var/lib/secnews/cyber_news_24h.json
                                              │
   :05 UTC ───► processor ──► classify ──► dedup ──► HTML digest ──► Telegram
```

## Features

- 30+ feeds: vendor blogs (Google, Mozilla, Mandiant, Unit 42, Talos…), news sites (BleepingComputer, KrebsOnSecurity, The Register, Dark Reading…), researcher Mastodon (Troy Hunt, Will Dormann), CISA KEV, Exploit-DB, and more.
- 48h URL dedup + fuzzy title match (catches the same CVE story across multiple outlets).
- Aggregator sources (HN, Full Disclosure) are filtered against a security keyword list.
- Three-tier severity classification (`CRITICAL / HIGH / MEDIUM`) with a `DISCARD` default — only what matters reaches the chat.
- HTML-formatted Telegram digest with auto-chunking at 4000 chars and a parse-failure fallback to plain text.
- Atomic JSON writes, retry/backoff on HTTP, `flock`-protected cron, log rotation.
- Idle-hour "funny filler" message, throttled to once per hour.

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

## Quick install (Kali / Debian, root)

```bash
git clone git@github.com:pereirat2/secnews-scraper.git /opt/secnews
cd /opt/secnews
cp .env.example .env
chmod 600 .env
$EDITOR .env                 # set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID

bash scripts/install.sh
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

Severity rules live in `secnews/processor.py` as four pattern lists:

- `DISCARD_PATTERNS` — drops the item entirely (matched first).
- `CRITICAL_PATTERNS` — actively-exploited, emergency, in-the-wild, etc.
- `HIGH_PATTERNS` — CVEs, RCE, ransomware, APTs, supply chain.
- `MEDIUM_PATTERNS` — generic vulnerabilities, breaches, phishing.

Anything not matching any list defaults to `discard`.

## Operational notes

- The first run after install will dump up to 24h of articles in one digest (window seeds from empty). Expect a long message.
- If you want a clean start, delete `/var/lib/secnews/cyber_news_24h.json` — the next collector run will rebuild it.
- The dedup cache (`cyber_news_dedup.json`) persists across runs and self-purges entries older than 48h.
- A failed Telegram send leaves items as `processed: false`, so the next run retries.

## Security

- `.env` is gitignored. Never commit it.
- `chmod 600 .env`. The bot token grants full control of the bot.
- If the token is ever leaked, revoke it immediately via `@BotFather` and rotate.
- Cron runs as `root`. Reduce to a service user if you prefer; both directories should then be `chown`ed accordingly.

## License

Personal project. No license — all rights reserved.
