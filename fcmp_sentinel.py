#!/usr/bin/env python3
"""
fcmp_sentinel.py — watches Monero development for FCMP++ mainnet activation signals.

Severity model:
  0 = noise    (logged, no alert)
  1 = low      (ntfy only)
  2 = high     (ntfy + email)
  3 = CRITICAL (ntfy urgent + email + Pushover emergency, re-alerts until acknowledged)

All credentials are read from the environment and injected by GitHub Actions.
No secret is ever hardcoded in this file.
"""

import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path
from xml.etree import ElementTree

# ═══════════════════════════════════════════════════════════════════
#  CONFIG — edit the lists below to change what is watched
# ═══════════════════════════════════════════════════════════════════

STATE_FILE = Path("state/state.json")

# ── Watched feeds ───────────────────────────────────────────────────
FEEDS = {
    "monero-releases":  "https://github.com/monero-project/monero/releases.atom",
    "monero-tags":      "https://github.com/monero-project/monero/tags.atom",
    "monero-commits":   "https://github.com/monero-project/monero/commits/master.atom",
    "getmonero-blog":   "https://www.getmonero.org/feed.xml",
    "monero-observer":  "https://monero.observer/feed-mini.xml",
    "mo-stories":       "https://monero.observer/feed-stories-mini.xml",
    "mo-dev":           "https://monero.observer/feed-dev.xml",
    "mo-breaking":      "https://monero.observer/feed-breaking.xml",
}

# ── Watched raw source files ────────────────────────────────────────
# NOTE: hardforks.cpp lives in src/hardforks/, NOT src/cryptonote_basic/
RAW_FILES = {
    "hardforks": "https://raw.githubusercontent.com/monero-project/monero/master/src/hardforks/hardforks.cpp",
    "version":   "https://raw.githubusercontent.com/monero-project/monero/master/src/version.cpp.in",
}

# ── GitHub API endpoints (milestones, PRs, official site posts) ─────
GITHUB_API = {
    "milestones": "https://api.github.com/repos/monero-project/monero/milestones",
    "open-prs":   "https://api.github.com/search/issues?q=repo:monero-project/monero+is:pr+is:open+fcmp++",
    # latest commit touching the official blog source; catches official prose
    # (e.g. the unlock-time deprecation post) before it reaches the Atom feed
    "site-posts": "https://api.github.com/repos/monero-project/monero-site/commits?path=_posts&per_page=1",
}

# ── Keyword escalation ──────────────────────────────────────────────
# An item scoring 0 or 1 that contains these gets bumped up.
CRITICAL_KEYWORDS = [
    r"mainnet activation", r"fork height", r"activation height",
    r"hard fork.*height", r"hf\s*schedul", r"fork.*datetime",
    r"network upgrade", r"v0\.(19|20)\.\d",
]
HIGH_KEYWORDS = [
    r"fcmp\+\+", r"fcmpp", r"full-chain membership",
    r"stressnet", r"hard fork", r"hardfork",
    # NOTE: "audit" and "v0.19./v0.20." were removed from HIGH to reduce noise.
    # Add them back if you want maximum sensitivity:
    # r"audit", r"v0\.19\.", r"v0\.20\.",
]

# ── Runtime tunables ────────────────────────────────────────────────
HTTP_TIMEOUT        = 25
USER_AGENT          = "fcmp-sentinel/1.0 (+https://github.com/)"
FEED_IDS_KEPT       = 60      # per feed, how many entry IDs to remember
ALERTED_KEEP_DAYS   = 45      # prune dedupe keys older than this

# ═══════════════════════════════════════════════════════════════════
#  Credentials — read from environment, injected by GitHub Actions.
#  Everything below is a NAME; values live in repo Settings → Secrets.
#  Each line below is a swap point if you ever rename a secret.
# ═══════════════════════════════════════════════════════════════════

NTFY_TOPIC     = os.environ.get("NTFY_TOPIC", "")                       # ◄── secret
NTFY_URL       = os.environ.get("NTFY_URL") or "https://ntfy.sh"        # ◄── handles empty string
GH_TOKEN       = os.environ.get("GH_TOKEN", "")                         # ◄── secret
HC_PING_URL    = os.environ.get("HC_PING_URL", "")                      # ◄── secret
PUSHOVER_TOKEN = os.environ.get("PUSHOVER_TOKEN", "")                   # ◄── secret
PUSHOVER_USER  = os.environ.get("PUSHOVER_USER", "")                    # ◄── secret
SMTP_HOST      = os.environ.get("SMTP_HOST", "")                        # ◄── secret
SMTP_PORT      = int(os.environ.get("SMTP_PORT") or "465")
SMTP_USER      = os.environ.get("SMTP_USER", "")                        # ◄── secret
SMTP_PASS      = os.environ.get("SMTP_PASS", "")                        # ◄── secret
ALERT_EMAIL    = os.environ.get("ALERT_EMAIL", "")                      # ◄── secret

# Set the SEND_TEST_ALERT secret to "1" to fire one test alert per run.
# Set it back to empty/delete it when done — no code edits required.
SEND_TEST_ALERT = os.environ.get("SEND_TEST_ALERT", "").strip().lower() in ("1", "true", "yes", "on")

# ═══════════════════════════════════════════════════════════════════
#  HTTP helpers
# ═══════════════════════════════════════════════════════════════════

def log(msg):
    print(f"[{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S}Z] {msg}", flush=True)


def http_get(url, try_json=False, attempts=3):
    headers = {"User-Agent": USER_AGENT}
    if GH_TOKEN and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
        headers["Accept"] = "application/vnd.github+json"
    delay = 2
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                body = r.read().decode("utf-8", errors="replace")
                return json.loads(body) if try_json else body
        except Exception as e:
            if i == attempts - 1:
                log(f"  ! fetch failed: {url} -> {e}")
                return None
            time.sleep(delay)
            delay *= 2
    return None


def sha256(text):
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


# ═══════════════════════════════════════════════════════════════════
#  State
# ═══════════════════════════════════════════════════════════════════

def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True))


def prune_state(state, days=ALERTED_KEEP_DAYS):
    """Keep state.json from growing without bound."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    alerted = state.get("alerted", {})
    keep = {}
    for k, v in alerted.items():
        try:
            if datetime.fromisoformat(v) >= cutoff:
                keep[k] = v
        except Exception:
            keep[k] = v          # unparseable -> keep rather than lose dedupe
    state["alerted"] = keep

    for name, ids in state.get("feeds", {}).items():
        state["feeds"][name] = ids[:FEED_IDS_KEPT]


# ═══════════════════════════════════════════════════════════════════
#  Alerts
# ═══════════════════════════════════════════════════════════════════

def notify_ntfy(title, message, severity):
    if not NTFY_TOPIC:
        log("  ! ntfy skipped: NTFY_TOPIC is empty")
        return
    prio = {0: "2", 1: "3", 2: "4", 3: "5"}[severity]
    tags = {0: "eyes", 1: "mag", 2: "warning", 3: "rotating_light"}[severity]
    try:
        req = urllib.request.Request(
            f"{NTFY_URL.rstrip('/')}/{NTFY_TOPIC}", data=message.encode("utf-8"),
            headers={"Title": title.encode("ascii", "ignore").decode() or "FCMP+ Sentinel",
                     "Priority": prio, "Tags": tags},
            method="POST")
        urllib.request.urlopen(req, timeout=HTTP_TIMEOUT)
        log(f"  -> ntfy sent ({NTFY_URL.rstrip('/')}/{NTFY_TOPIC})")
    except Exception as e:
        log(f"  ! ntfy failed: {e}")


def notify_email(title, message, severity):
    if severity < 2 or not (SMTP_HOST and SMTP_USER and SMTP_PASS and ALERT_EMAIL):
        return
    try:
        import apprise
        a = apprise.Apprise()
        a.add(f"mailtos://{urllib.parse.quote(SMTP_USER)}:{urllib.parse.quote(SMTP_PASS)}"
              f"@{SMTP_HOST}:{SMTP_PORT}?to={urllib.parse.quote(ALERT_EMAIL)}")
        a.notify(title=title, body=message)
        log("  -> email sent")
    except ImportError:
        log("  ! apprise not installed; skipping email")
    except Exception as e:
        log(f"  ! email failed: {e}")


def notify_pushover(title, message, severity):
    if severity < 3 or not (PUSHOVER_TOKEN and PUSHOVER_USER):
        return
    try:
        data = urllib.parse.urlencode({
            "token": PUSHOVER_TOKEN, "user": PUSHOVER_USER,
            "title": title, "message": message[:1024],
            "priority": "2",          # emergency: repeats until acknowledged
            "retry": "60",            # re-alert every 60 seconds
            "expire": "3600",         # give up after 1 hour
            "sound": "siren",
        }).encode()
        urllib.request.urlopen(
            urllib.request.Request("https://api.pushover.net/1/messages.json", data=data),
            timeout=HTTP_TIMEOUT)
        log("  -> pushover EMERGENCY sent")
    except Exception as e:
        log(f"  ! pushover failed: {e}")


def alert(title, message, severity, source_key, state):
    """Fire all channels and record the alert in state for dedupe."""
    if severity >= 1:
        log(f"  ALERT [sev {severity}] {title}")
        notify_ntfy(title, message, severity)
        notify_email(title, message, severity)
        notify_pushover(title, message, severity)
    else:
        log(f"  (sev 0) {title}")
    state.setdefault("alerted", {})[source_key] = \
        datetime.now(timezone.utc).isoformat()
    return True


def already_alerted(state, key):
    return key in state.get("alerted", {})


# ═══════════════════════════════════════════════════════════════════
#  Severity scoring
# ═══════════════════════════════════════════════════════════════════

def score_text(text, base=0):
    s = base
    low = text.lower()
    if any(re.search(k, low) for k in HIGH_KEYWORDS):
        s = max(s, 2)
    if any(re.search(k, low) for k in CRITICAL_KEYWORDS):
        s = max(s, 3)
    return s


# ═══════════════════════════════════════════════════════════════════
#  Checks
# ═══════════════════════════════════════════════════════════════════

def check_feeds(state):
    """New entries in any watched RSS/Atom feed."""
    seen = state.setdefault("feeds", {})
    for name, url in FEEDS.items():
        body = http_get(url)
        if not body:
            continue
        entries = []
        try:
            root = ElementTree.fromstring(body)
            ns = {"a": "http://www.w3.org/2005/Atom"}
            if root.tag.endswith("feed"):                       # Atom
                for e in root.findall("a:entry", ns):
                    entries.append({
                        "id":    (e.findtext("a:id", "", ns) or "").strip(),
                        "title": (e.findtext("a:title", "", ns) or "").strip(),
                        "link":  (e.find("a:link", ns).get("href")
                                  if e.find("a:link", ns) is not None else ""),
                    })
            else:                                               # RSS
                for e in root.iter("item"):
                    entries.append({
                        "id":    (e.findtext("guid", "") or e.findtext("link", "") or "").strip(),
                        "title": (e.findtext("title", "") or "").strip(),
                        "link":  (e.findtext("link", "") or "").strip(),
                    })
        except ElementTree.ParseError as e:
            log(f"  ! feed parse error {name}: {e}")
            continue

        if not entries:
            continue

        seen_ids = set(seen.get(name, []))
        new = [e for e in entries if e["id"] and e["id"] not in seen_ids]

        if not seen_ids:
            log(f"  {name}: baseline ({len(entries)} entries recorded)")
        else:
            for e in new:
                sev = score_text(e["title"], base=1)
                key = f"feed:{name}:{e['id']}"
                if sev >= 1 and not already_alerted(state, key):
                    alert(f"[{name}] {e['title']}",
                          f"{e['title']}\n{e['link']}\n\nSource feed: {name}",
                          sev, key, state)

        seen[name] = [e["id"] for e in entries[:FEED_IDS_KEPT]]


def check_raw_files(state):
    """Line-diff raw source files. hardforks.cpp change = CRITICAL."""
    files = state.setdefault("files", {})
    for name, url in RAW_FILES.items():
        body = http_get(url)
        if body is None:
            continue
        digest = sha256(body)
        prev = files.get(name, {})

        if not prev:
            files[name] = {"hash": digest, "lines": body.splitlines()}
            log(f"  {name}: baseline hash {digest[:12]}")
            continue

        if digest == prev["hash"]:
            continue

        old_lines = set(prev.get("lines", []))
        added = [l.strip() for l in body.splitlines()
                 if l.strip() and l.strip() not in old_lines]
        files[name] = {"hash": digest, "lines": body.splitlines()}

        key = f"file:{name}:{digest}"
        if already_alerted(state, key):
            continue

        # hardforks.cpp is the single most important file in this project.
        if name == "hardforks":
            # mainnet_hard_forks rows look like:  { 16, 3456789, 0, 1700000000 },
            rows = [l for l in added if re.match(r"^\{\s*\d+\s*,", l)]
            detail = ("NEW HARD FORK TABLE ROW:\n" + "\n".join(rows)) if rows \
                     else "hardforks.cpp changed (no new table row parsed)"
            alert("CRITICAL: Monero hardforks.cpp changed",
                  f"{detail}\n\nFile: {url}\n\nDiff preview:\n" +
                  "\n".join(added[:25]),
                  3, key, state)

        elif name == "version":
            ver = [l for l in added if re.search(r"MONERO_VERSION", l, re.I)]
            sev = 3 if any(re.search(r"v0\.(19|20)\.", l, re.I) for l in added) else 2
            alert("Monero version.cpp changed",
                  f"{' '.join(ver) or 'version.cpp.in changed'}\n\n{url}\n\n" +
                  "\n".join(added[:25]), sev, key, state)


def check_github_api(state):
    """Milestones, open FCMP++ PR count, and official-site blog commits."""
    api = state.setdefault("api", {})

    # ── Milestones ──────────────────────────────────────────────────
    ms = http_get(GITHUB_API["milestones"], try_json=True)
    if isinstance(ms, list):
        summary = {m.get("title", "?"): m.get("state") for m in ms}
        prev = api.get("milestones")
        if prev and summary != prev:
            key = "api:milestones:" + sha256(json.dumps(summary, sort_keys=True))[:16]
            alert("Monero milestone list changed",
                  "Milestones changed:\n" + json.dumps(summary, indent=2),
                  2, key, state)
        api["milestones"] = summary

    # ── Open FCMP++ PR count ────────────────────────────────────────
    prs = http_get(GITHUB_API["open-prs"], try_json=True)
    if isinstance(prs, dict) and "total_count" in prs:
        total = prs["total_count"]
        prev = api.get("fcmp_prs")
        if prev is not None and total != prev:
            key = f"api:prs:{total}"
            sev = 2 if abs(total - prev) >= 2 else 1
            alert(f"FCMP++ open PR count changed: {prev} -> {total}",
                  f"Open FCMP++ PRs: {prev} -> {total}\n{GITHUB_API['open-prs']}",
                  sev, key, state)
        api["fcmp_prs"] = total

    # ── Official website blog source (catches prose before the feed) ─
    posts = http_get(GITHUB_API["site-posts"], try_json=True)
    if isinstance(posts, list) and posts:
        latest = posts[0]
        sha = latest.get("sha", "")
        msg = (latest.get("commit", {}).get("message", "") or "").splitlines()
        msg = msg[0] if msg else ""
        prev = api.get("site_posts_sha")
        api["site_posts_sha"] = sha
        if prev and prev != sha:
            sev = score_text(msg, base=2)
            key = f"api:site-posts:{sha}"
            if not already_alerted(state, key):
                alert("Monero website _posts changed",
                      f"Latest blog-source commit:\n{msg}\n\n"
                      "https://github.com/monero-project/monero-site/commits/master/_posts",
                      sev, key, state)


# ═══════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════

def ping_hc(path=""):
    if not HC_PING_URL:
        return
    try:
        urllib.request.urlopen(HC_PING_URL.rstrip("/") + path, timeout=15)
    except Exception:
        pass


def main():
    log("=" * 60)
    log("FCMP+ Sentinel run starting")
    ping_hc("/start")

    state = load_state()
    try:
        log("-> checking feeds")
        check_feeds(state)
        log("-> checking raw source files")
        check_raw_files(state)
        log("-> checking GitHub API")
        check_github_api(state)

        state["last_run"] = datetime.now(timezone.utc).isoformat()
        state["run_count"] = state.get("run_count", 0) + 1

        if SEND_TEST_ALERT:
            log("SEND_TEST_ALERT is set -> firing test alert")
            alert("TEST: alert path check",
                  "If you are reading this, your alert pipeline works.",
                  3, f"test:{int(time.time())}", state)

        prune_state(state)
        save_state(state)
        log(f"OK run complete (#{state['run_count']})")
        ping_hc("")             # success ping
        return 0
    except Exception as e:
        log(f"FATAL: {e}")
        import traceback
        traceback.print_exc()
        ping_hc("/fail")
        return 1


if __name__ == "__main__":
    sys.exit(main())
