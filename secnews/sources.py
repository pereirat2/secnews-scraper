"""Feed source registry.

Each source is a tuple: (name, url, is_json_api, extra_headers).
`AGGREGATOR_SOURCES` are noisy/general — we apply keyword filtering to those.
"""

from __future__ import annotations

from datetime import datetime, timezone


def _full_disclosure_url() -> str:
    """seclists.org organizes the FullDisclosure archive by /YYYY/MMM/."""
    now = datetime.now(timezone.utc)
    return f"https://seclists.org/fulldisclosure/{now.year}/{now.strftime('%b')}/date"


SOURCES: list[tuple[str, str, bool, dict]] = [
    # === Core security news ===
    ("TheHackerNews", "https://feeds.feedburner.com/TheHackersNews", False, {}),
    ("SecurityAffairs", "https://securityaffairs.com/feed", False, {}),
    ("KrebsOnSecurity", "https://krebsonsecurity.com/feed/", False, {}),
    ("DarkReading", "https://www.darkreading.com/rss.xml", False, {}),
    ("TheRegister", "https://www.theregister.com/security/headlines.atom", True, {}),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", False, {"User-Agent": "curl/8.0"}),

    # === Mastodon researchers (infosec.exchange) ===
    ("Troy Hunt", "https://infosec.exchange/@troyhunt.rss", False, {}),
    ("Will Dormann", "https://infosec.exchange/@wdormann.rss", False, {}),
    ("SwiftOnSecurity", "https://infosec.exchange/@SwiftOnSecurity.rss", False, {}),

    # === Threat intelligence & vendor research ===
    ("Google Security", "https://security.googleblog.com/atom.xml", False, {}),
    ("Mozilla Security", "https://blog.mozilla.org/security/feed/", False, {}),
    ("Mandiant", "https://www.mandiant.com/resources/blog/rss.xml", False, {}),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/", False, {}),
    ("Checkpoint", "https://research.checkpoint.com/feed/", False, {}),
    ("Talos", "https://blog.talosintelligence.com/rss/", False, {}),
    ("Securelist", "https://securelist.com/feed/", False, {}),
    ("SentinelOne", "https://www.sentinelone.com/blog/rss/", False, {}),
    ("Crowdstrike", "https://www.crowdstrike.com/blog/feed/", False, {}),
    ("Proofpoint", "https://www.proofpoint.com/us/rss.xml", False, {}),
    ("Wiz Blog", "https://www.wiz.io/feed/rss.xml", False, {}),
    ("WeLiveSecurity", "https://www.welivesecurity.com/feed/", False, {}),

    # === Security news sites ===
    ("The Record", "https://therecord.media/feed/", False, {}),
    ("SecurityWeek", "https://www.securityweek.com/feed/", False, {}),
    ("InfosecMagazine", "https://www.infosecurity-magazine.com/rss/news/", False, {}),
    ("ThreatCluster", "https://threatcluster.io/rss", False, {}),
    ("TheHackerWire", "https://www.thehackerwire.com/rss", False, {"User-Agent": "Mozilla/5.0"}),

    # === Aggregators & community (filtered by keywords) ===
    ("HN RSS", "https://news.ycombinator.com/rss", False, {}),
    ("FullDisclosure", _full_disclosure_url(), False, {}),

    # === Government & CERT JSON feeds ===
    ("CISA_KEV", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", True, {}),

    # === Exploit & bug bounty ===
    ("Exploit-DB", "https://www.exploit-db.com/rss.xml", False, {}),
]


AGGREGATOR_SOURCES: set[str] = {"HN RSS", "FullDisclosure"}
HTML_SCRAPE_SOURCES: set[str] = {"FullDisclosure"}


KEYWORD_INCLUDE_PATTERNS: list[str] = [
    r"CVE-\d{4}-", r"zero.?day", r"0[- ]day",
    r"vulnerabilit", r"exploit", r"patch",
    r"\bRCE\b", r"remote code execution", r"privilege escalation",
    r"malware", r"ransomware", r"trojan", r"backdoor", r"spyware", r"stealer",
    r"infostealer", r"botnet", r"rootkit",
    r"breach", r"data breach", r"data leak", r"credential",
    r"compromise", r"intrusion", r"phish",
    r"\bAPT\b", r"hacker", r"cyberattack", r"supply chain",
    r"CISA", r"security advisory", r"\balert\b", r"\bflaw\b",
    r"cyber(security)?", r"infosec",
]
