# b0W7yiDA0lgq7Z57kDhxdH3uGjGca7M6M# FCMP+ Sentinel

A $0/month, no-VPS watchdog that watches Monero development for signals that
FCMP++ is moving toward mainnet activation, and pushes text-style alerts
when something critical happens.

## What it watches

| Source | Type | Why |
|---|---|---|
| `monero-project/monero` releases + tags | Atom feed | new `v0.19.x` / `v0.20.x` release = release signal |
| `monero-project/monero` commits | Atom feed | commit chatter |
| `src/hardforks/hardforks.cpp` | raw file, line-diffed | a new fork table row = the activation signal |
| `src/version.cpp.in` | raw file, line-diffed | version bump = release signal |
| getmonero.org blog | Atom feed | official prose |
| `monero-project/monero-site` `_posts` | GitHub API | official blog source, catches posts before the feed does |
| Monero Observer (4 feeds) | Atom/RSS | community press |
| GitHub milestones + open FCMP++ PRs | GitHub API | governance + dev activity |

## Alert levels

| Level | Name | Channels | Meaning |
|---|---|---|---|
| 0 | noise | log only | matched nothing notable; kept for situational awareness |
| 1 | low | ntfy | relevant mention, no action needed |
| 2 | high | ntfy + email | FCMP++ / version / milestone movement worth reading now |
| 3 | CRITICAL | ntfy urgent + email + Pushover emergency (repeats every 60s until acknowledged) | `hardforks.cpp` changed, a `v0.19.x`/`v0.20.x` bump, or explicit activation-height language |

Level 3 is deliberately reserved for code and explicit activation language.
A random article titled "FCMP++" will never reach it.

## Secrets (Settings -> Secrets and variables -> Actions)

No secret is ever stored in a file. The script reads everything from
environment variables; the workflow wires secrets into that environment.

| Secret | Where to get it |
|---|---|
| `NTFY_TOPIC` | the topic name you invented (this is the password) |
| `GH_TOKEN` | fine-grained PAT, read-only, scoped to `monero-project/monero` |
| `HC_PING_URL` | healthchecks.io ping URL |
| `PUSHOVER_TOKEN` | Pushover app API token |
| `PUSHOVER_USER` | Pushover user key |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` | email provider + app password |
| `ALERT_EMAIL` | where email alerts go |
| `SEND_TEST_ALERT` | set to `1` to fire a test alert; blank otherwise |

`SMTP_*`, `PUSHOVER_*`, and `NTFY_URL` are all optional — missing ones degrade
silently rather than crashing the run.

## Testing the alert path

1. Add a repo secret `SEND_TEST_ALERT` with value `1`.
2. Actions -> FCMP+ Sentinel -> Run workflow.
3. Confirm ntfy + email + Pushover all fire.
4. Delete the `SEND_TEST_ALERT` secret (or set it blank).

## Safety nets

- healthchecks.io (period 15 min, grace 30 min) emails you if the sentinel
  stops running for any reason — including GitHub silently disabling the cron
  after 60 days of repo inactivity.
- Push retries: the state-commit step retries 5x with backoff.

## Known caveat

This makes you early to information, not early to a known date. Everything it
watches is public the instant it appears. There is no committed FCMP++
activation date; the honest tracker is the three gates — privacy audit
(reported complete May 2026), stressnet stability, and a coordinated network
upgrade.
