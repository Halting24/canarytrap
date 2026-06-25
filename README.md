<h1 align="center">canarytrap</h1>
<p align="center"><b>Deception engineering in a single file.</b> Plant honeytokens, get pinged the instant an intruder touches one.</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/deps-stdlib%20(+rich)-success">
  <img src="https://img.shields.io/badge/technique-deception%20%C2%B7%20honeytokens-7c4dff">
  <img src="https://img.shields.io/badge/license-MIT-green">
</p>

---

Most breaches are detected months late. Honeytokens flip that: you scatter fake-but-tempting credentials and files where an attacker who is already inside will find them, and the moment one is touched you get a high-signal, near-zero-false-positive alert. `canarytrap` mints them and runs the trap.

## Token types

| `mint kind` | what it creates | trips when... |
|-------------|----------------|---------------|
| `url` | a bare tripwire link | anyone visits it |
| `doc` | a "CONFIDENTIAL" HTML file with a 1x1 tracking pixel | the document is opened or previewed in a browser |
| `env` | a believable `.env` with a tripwire `WEBHOOK_URL` | a tool or SSRF fetches the webhook field |
| `aws` | a realistic `AKIA...` credentials file | the embedded callback URL is hit (or wire the key to CloudTrail) |
| `slack` | a JSON config with a decoy Slack webhook URL plus a canary ping field | automation reads and exercises the config |
| `apikey` | a YAML credentials file with a callback URL | any script that calls the callback_url field |
| `ssh` | a decoy OpenSSH private key + companion `.pub` with a verify URL in the comment | automation reads the pubkey comment and fetches the verify URL |
| `db` | a decoy `.pgpass` and DSN config with a health-check URL | any tool that validates the DSN by fetching the health-check |
| `kubeconfig` | a decoy kubeconfig YAML with a cluster health-check extension URL | kubectl or CI tooling that probes the cluster endpoint |

## Install and run

```bash
git clone https://github.com/Halting24/canarytrap && cd canarytrap
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # just 'rich' for the dashboard

export CANARYTRAP_DATA=/path/to/data-dir  # optional, defaults to ./canarytrap_data
```

## Quick demo

```bash
# Mint a few tokens
canarytrap mint url        --name prod-backup-link  --label ops
canarytrap mint aws        --name ci-deploy-key     --expire 90
canarytrap mint slack      --name internal-alerts
canarytrap mint ssh        --name prod-server       --label infrastructure
canarytrap mint kubeconfig --name k8s-prod

# Start the listener. It also serves a live HTML dashboard at GET /
canarytrap listen --port 8000 --webhook https://discord.com/api/webhooks/...

# In another terminal - live trip feed
canarytrap watch
```

When a token is hit:

```text
TRIPPED  'ci-deploy-key' [aws]  from 203.0.113.9 (attacker.example.com)
         EvilScanner/1.0 (recon)  @ 2026-06-25T10:14:22
```

A macOS desktop notification fires, the webhook is posted, and the event is stored in SQLite.

## Commands reference

### `mint`

```
canarytrap mint <kind> --name <name> [--url <base-url>] [--label <tag>] [--expire <days>]
```

- `--name` - human-readable name shown in alerts (required)
- `--url` - public base URL of your listener (default `http://localhost:8000`)
- `--label` - optional tag for grouping tokens
- `--expire <days>` - record an informational expiry date (does not auto-delete)

Examples:

```bash
canarytrap mint url       --name "prod-backup-link" --label ops
canarytrap mint doc       --name "Q3_passwords"
canarytrap mint env       --name "staging-.env"
canarytrap mint aws       --name "ci-deploy-key"    --expire 90
canarytrap mint slack     --name "internal-alerts"
canarytrap mint apikey    --name "stripe-live-key"  --label payments
canarytrap mint ssh       --name "prod-server"      --url https://canary.yourco.com
canarytrap mint db        --name "postgres-prod"
canarytrap mint kubeconfig --name "k8s-prod-admin"
```

### `listen`

```
canarytrap listen [--host 0.0.0.0] [--port 8000] [--webhook <url>]
```

Starts the HTTP listener. Two endpoints:

- `GET /t/<id>` - trips the token; returns a 1x1 transparent GIF so the client sees nothing
- `GET /` (or `/dashboard`) - live HTML status page (auto-refreshes every 10 s)

On each trip:
- Prints a red terminal alert with source IP, reverse-DNS hostname, user-agent, and timestamp
- Fires a macOS `display notification` via `osascript` (works on Mac; silent elsewhere)
- POSTs to the Slack or Discord webhook if `--webhook` is provided
- Enriches the stored record with a reverse-DNS lookup (2 s timeout, non-blocking)

```bash
canarytrap listen --port 8080 --webhook https://hooks.slack.com/services/T.../B.../...
```

### `tokens`

```
canarytrap tokens [--kind <kind>] [--active]
```

Lists all honeytokens with id, kind, name, label, status, trip count, created date, expiry, and tripwire URL.

```bash
canarytrap tokens
canarytrap tokens --kind aws
canarytrap tokens --active
canarytrap tokens --kind ssh --active
```

### `watch`

```
canarytrap watch
```

A live auto-refreshing terminal table (requires `rich`) showing the 20 most recent triggers with columns: time, token name, kind, source IP, reverse-DNS hostname, user-agent. Falls back to plain text without `rich`.

### `triggers`

```
canarytrap triggers
```

Dumps the full trigger log as JSON to stdout. Pipe to `jq` for filtering:

```bash
canarytrap triggers | jq '.[] | select(.kind=="aws")'
```

### `report`

```
canarytrap report [--html <file>]
```

Prints a summary with total trips, unique source IPs, top triggered tokens, top source IPs, trips by token kind, and first/last seen timestamps. Optionally exports a styled standalone HTML report.

```bash
canarytrap report
canarytrap report --html /tmp/canary-report.html
open /tmp/canary-report.html
```

### `export`

```
canarytrap export [--format json|csv|cef]
```

Exports the full trigger log for SIEM or downstream tooling.

- `json` (default) - JSON array, one record per line
- `csv` - RFC 4180 CSV with headers
- `cef` - ArcSight Common Event Format (CEF:0) suitable for Splunk, QRadar, etc.

```bash
canarytrap export --format csv  > triggers.csv
canarytrap export --format cef  | nc siem.internal 514
canarytrap export --format json | jq 'group_by(.ip)[]'
```

### `disarm`

```
canarytrap disarm <token-id>
```

Marks a token as inactive (revoked). It remains in the database for audit purposes and will still appear in reports, but `tokens --active` will no longer show it.

```bash
canarytrap disarm a3f8b12c4e9d0127
```

## Storage

State is kept in a SQLite database (`canarytrap.db`) under `CANARYTRAP_DATA`. On first run, any legacy `tokens.json` and `triggers.json` from earlier versions are automatically migrated and renamed to `*.json.migrated`.

```text
canarytrap_data/
  canarytrap.db           # all tokens and triggers
  Q3_passwords.html       # minted doc artifact
  staging-.env.env        # minted env artifact
  ci-deploy-key.credentials  # minted aws artifact
  ...
```

## Alerting flow

```
attacker hits /t/<id>
       |
       v
  record trigger in SQLite (with rDNS enrichment)
       |
       +---> red terminal alert (ANSI)
       |
       +---> macOS desktop notification (osascript)
       |
       +---> Slack/Discord webhook POST (if --webhook set)
```

## Real deployment

```bash
# On a VPS or behind a Cloudflare tunnel:
export CANARYTRAP_DATA=/var/lib/canarytrap

# Mint tokens pointing at your public host
canarytrap mint aws --name "ci-deploy-key" --url https://canary.yourco.com

# Run listener with a Discord alert webhook
canarytrap listen --port 443 --webhook https://discord.com/api/webhooks/...
```

> Tokens default to `http://localhost:8000`. For real use, pass `--url https://your-canary-host` at mint time.

## Why it stands out

Real intrusion detection that is the opposite of a noisy scanner: it stays silent until something is genuinely wrong. The `listen` command doubles as a live HTML dashboard. Inspired by Thinkst Canary and canarytokens.org, rebuilt from scratch in under 600 lines of mostly-stdlib Python with zero external dependencies beyond `rich`.

## Use responsibly

Deploy honeytokens only on assets you own or are authorized to defend.

---
<p align="center"><i>Part of a cybersecurity project series - <a href="https://github.com/Halting24">@Halting24</a></i></p>
