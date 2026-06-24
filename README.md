<h1 align="center">🪤 canarytrap</h1>
<p align="center"><b>Deception engineering in a single file.</b> Plant honeytokens, get pinged the instant an intruder touches one.</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/deps-stdlib%20(+rich)-success">
  <img src="https://img.shields.io/badge/technique-deception%20%C2%B7%20honeytokens-7c4dff">
  <img src="https://img.shields.io/badge/license-MIT-green">
</p>

---

Most breaches are detected **months** late. Honeytokens flip that: you scatter fake-but-tempting credentials and files where an attacker who's already inside will find them, and the moment one is touched you get a high-signal, near-zero-false-positive alert. `canarytrap` mints them and runs the trap.

### Token types

| `mint` | what it is | trips when… |
|--------|-----------|-------------|
| `url`  | a tripwire link | anyone visits it |
| `doc`  | a "CONFIDENTIAL" HTML file with a 1×1 tracking pixel | the document is opened/previewed |
| `env`  | a believable `.env` with a tripwire `WEBHOOK_URL`/`API_BASE` | a tool or SSRF fetches it |
| `aws`  | a realistic decoy `AKIA…` credentials file | the embedded callback is hit (or wire the key to CloudTrail) |

## Demo

```text
$ canarytrap mint url --name prod-backup-link
🪤  minted [url] 'prod-backup-link'  id=032e030357a14752
    tripwire: http://localhost:8000/t/032e030357a14752

$ canarytrap listen --port 8000 &
👂 canarytrap listening on http://0.0.0.0:8000  (3 tokens armed)

# …attacker finds and opens the link…
🚨 TRIPPED  'prod-backup-link' [url]  from 203.0.113.7  curl/8.4  @ 2026-06-24T13:35:53
```

```text
$ canarytrap watch
🪤 canarytrap — 1 triggers · 3 tokens armed
 time                  token              kind   source IP     user-agent
 2026-06-24T13:35:53   prod-backup-link   url    203.0.113.7   EvilScanner/1.0 (pwned)
```

## Install & run

```bash
git clone https://github.com/Halting24/canarytrap && cd canarytrap
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # just 'rich' for the dashboard

canarytrap mint doc --name "Q3_passwords"        # writes a booby-trapped .html
canarytrap mint env --name "staging-.env"
canarytrap listen --port 8000 --webhook https://discord.com/api/webhooks/...
canarytrap watch                                  # live dashboard
```

> Tokens default to `http://localhost:8000`. For real use, run `listen` on a host an attacker can reach (or a tunnel) and mint with `--url https://your-canary-host`.

## How it works

- Every token gets a unique id and a `…/t/<id>` tripwire URL.
- The `doc`/`env`/`aws` artifacts **embed that URL** (pixel, webhook field, callback comment), so touching the artifact pings the listener.
- The listener records `{time, token, kind, source IP, user-agent}`, prints a 🔔 alert, optionally fires a Slack/Discord webhook, and returns a transparent pixel so the attacker sees nothing.
- State is plain JSON (`canarytrap_data/`) — easy to inspect or ship to a SIEM.

## Why it stands out

Real intrusion detection that's the *opposite* of a noisy scanner: it stays silent until something is genuinely wrong. Inspired by Thinkst Canary / canarytokens, rebuilt from scratch in <300 lines of mostly-stdlib Python.

## ⚠️ Use responsibly

Deploy honeytokens only on assets **you own or are authorized to defend**.

---
<p align="center"><i>Part of a cybersecurity project series · <a href="https://github.com/Halting24">@Halting24</a></i></p>
