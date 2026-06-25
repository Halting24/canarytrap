#!/usr/bin/env python3
"""
canarytrap - deception engineering in a single file.

Mint believable honeytokens (decoy AWS keys, Slack webhooks, SSH keys,
database configs, kubeconfigs, generic API key files, a fake .env,
tripwire URLs, a booby-trapped document with a tracking pixel), drop
them where an intruder will find them, then run the listener. The moment
a token is touched you get an instant alert with the attacker's IP,
reverse-DNS name, user-agent and timestamp - early-warning that someone
is already inside, with near-zero false positives.

    canarytrap mint url       --name "prod-backup-link"
    canarytrap mint doc       --name "Q3_passwords"      # HTML w/ tracking pixel
    canarytrap mint env       --name "staging-.env"
    canarytrap mint aws       --name "ci-deploy-key"
    canarytrap mint slack     --name "internal-alerts"   # decoy Slack webhook URL
    canarytrap mint apikey    --name "stripe-key"        # generic API key file
    canarytrap mint ssh       --name "prod-server"       # decoy SSH private key
    canarytrap mint db        --name "postgres-prod"     # decoy .pgpass / DSN
    canarytrap mint kubeconfig --name "k8s-prod"         # decoy kubeconfig
    canarytrap listen         --port 8000                # start the trap + dashboard
    canarytrap watch                                     # live trigger dashboard
    canarytrap tokens         --kind aws --active        # filtered list
    canarytrap report         --html report.html         # stats + HTML export
    canarytrap export         --format json              # SIEM-friendly export
    canarytrap triggers                                  # dump trigger log
    canarytrap disarm <id>                              # revoke a token

Self-contained demo: tokens point at http://localhost:8000 by default.
For real use, run `listen` on a host an attacker can reach (or behind a
tunnel) and pass --url https://your-canary-host.
"""
from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import http.server
import io
import json
import os
import secrets
import socket
import socketserver
import sqlite3
import subprocess
import sys
import time
import threading
import uuid
from pathlib import Path
from textwrap import dedent
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------
DATA = Path(os.environ.get("CANARYTRAP_DATA", Path.cwd() / "canarytrap_data"))
DB_PATH = DATA / "canarytrap.db"
# Legacy JSON paths - only used during migration
_LEGACY_TOKENS_JSON = DATA / "tokens.json"
_LEGACY_TRIGGERS_JSON = DATA / "triggers.json"

PIXEL = base64.b64decode(  # 1x1 transparent gif
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

VALID_KINDS = ("url", "doc", "env", "aws", "slack", "apikey", "ssh", "db", "kubeconfig")


# ---------------------------------------------------------------------------
# SQLite storage
# ---------------------------------------------------------------------------
def _db() -> sqlite3.Connection:
    """Return a connection to the canarytrap SQLite database, creating tables and
    migrating legacy JSON data on first use."""
    DATA.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(dedent("""
        CREATE TABLE IF NOT EXISTS tokens (
            id          TEXT PRIMARY KEY,
            kind        TEXT NOT NULL,
            name        TEXT NOT NULL,
            created     TEXT NOT NULL,
            url         TEXT NOT NULL,
            label       TEXT,
            active      INTEGER NOT NULL DEFAULT 1,
            expire_date TEXT
        );
        CREATE TABLE IF NOT EXISTS triggers (
            rowid       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            token_id    TEXT NOT NULL,
            name        TEXT NOT NULL,
            kind        TEXT NOT NULL,
            ip          TEXT NOT NULL,
            rdns        TEXT,
            ua          TEXT
        );
    """))
    con.commit()
    _migrate_legacy(con)
    return con


def _migrate_legacy(con: sqlite3.Connection) -> None:
    """Migrate legacy tokens.json and triggers.json into SQLite (one-time)."""
    migrated = False
    if _LEGACY_TOKENS_JSON.exists():
        try:
            rows = json.loads(_LEGACY_TOKENS_JSON.read_text())
            for r in rows:
                con.execute(
                    "INSERT OR IGNORE INTO tokens (id,kind,name,created,url,active)"
                    " VALUES (?,?,?,?,?,1)",
                    (r.get("id"), r.get("kind"), r.get("name"),
                     r.get("created"), r.get("url")),
                )
            con.commit()
            _LEGACY_TOKENS_JSON.rename(_LEGACY_TOKENS_JSON.with_suffix(".json.migrated"))
            migrated = True
        except Exception as e:
            print(f"   (legacy tokens migration warning: {e})")
    if _LEGACY_TRIGGERS_JSON.exists():
        try:
            rows = json.loads(_LEGACY_TRIGGERS_JSON.read_text())
            for r in rows:
                con.execute(
                    "INSERT INTO triggers (ts,token_id,name,kind,ip,ua)"
                    " VALUES (?,?,?,?,?,?)",
                    (r.get("ts"), r.get("id", ""), r.get("name", ""),
                     r.get("kind", ""), r.get("ip", ""), r.get("ua", "")),
                )
            con.commit()
            _LEGACY_TRIGGERS_JSON.rename(_LEGACY_TRIGGERS_JSON.with_suffix(".json.migrated"))
            migrated = True
        except Exception as e:
            print(f"   (legacy triggers migration warning: {e})")
    if migrated:
        print("   (legacy JSON data migrated to SQLite)")


def _token_by_id(con: sqlite3.Connection, tid: str) -> Optional[sqlite3.Row]:
    return con.execute("SELECT * FROM tokens WHERE id=?", (tid,)).fetchone()


def _all_tokens(
    con: sqlite3.Connection,
    kind: Optional[str] = None,
    active_only: bool = False,
) -> list[sqlite3.Row]:
    sql = "SELECT * FROM tokens WHERE 1=1"
    params: list[Any] = []
    if kind:
        sql += " AND kind=?"
        params.append(kind)
    if active_only:
        sql += " AND active=1"
    sql += " ORDER BY created DESC"
    return con.execute(sql, params).fetchall()


def _all_triggers(con: sqlite3.Connection, limit: int = 0) -> list[sqlite3.Row]:
    sql = "SELECT * FROM triggers ORDER BY ts DESC"
    if limit:
        sql += f" LIMIT {int(limit)}"
    return con.execute(sql).fetchall()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _now() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def _safe(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)


def _rdns(ip: str) -> str:
    """Reverse-DNS lookup; returns empty string on failure."""
    try:
        # strip port if present (IPv4)
        addr = ip.split(",")[0].strip()
        result = socket.gethostbyaddr(addr)
        return result[0]
    except Exception:
        return ""


def _notify_macos(title: str, body: str) -> None:
    """Fire a macOS desktop notification via osascript (no-op on non-Mac)."""
    try:
        safe_title = title.replace('"', "'")
        safe_body = body.replace('"', "'")
        subprocess.run(
            ["osascript", "-e",
             f'display notification "{safe_body}" with title "{safe_title}"'],
            capture_output=True,
            timeout=3,
        )
    except Exception:
        pass


def _post_webhook(url: str, text: str) -> None:
    """POST a message to a Slack- or Discord-compatible webhook URL."""
    try:
        import urllib.request
        body = json.dumps({"content": text, "text": text}).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"   (webhook POST failed: {e})")


def _console():
    try:
        from rich.console import Console
        return Console()
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# Mint
# ---------------------------------------------------------------------------
def mint(
    kind: str,
    name: str,
    base_url: str,
    label: Optional[str] = None,
    expire_days: Optional[int] = None,
) -> dict:
    """Create and store a new honeytoken of the requested kind."""
    tid = uuid.uuid4().hex[:16]
    created = _now()
    url = f"{base_url.rstrip('/')}/t/{tid}"
    expire_date: Optional[str] = None
    if expire_days is not None and expire_days > 0:
        expire_date = (
            dt.datetime.now() + dt.timedelta(days=expire_days)
        ).date().isoformat()

    con = _db()
    con.execute(
        "INSERT INTO tokens (id,kind,name,created,url,label,active,expire_date)"
        " VALUES (?,?,?,?,?,?,1,?)",
        (tid, kind, name, created, url, label, expire_date),
    )
    con.commit()
    con.close()

    print(f"[mint] [{kind}] '{name}'  id={tid}")
    if label:
        print(f"       label: {label}")
    if expire_date:
        print(f"       expires: {expire_date}")
    print(f"       tripwire: {url}\n")

    _write_artifact(kind, name, url, tid, base_url)
    return {"id": tid, "kind": kind, "name": name, "created": created, "url": url}


def _write_artifact(kind: str, name: str, url: str, tid: str, base_url: str) -> None:
    """Write the on-disk artifact file (if applicable) for a token kind."""
    DATA.mkdir(parents=True, exist_ok=True)

    if kind == "url":
        print("Drop this link somewhere tempting (a bookmark, a README, a Slack pin):")
        print(f"    {url}")

    elif kind == "doc":
        path = DATA / f"{_safe(name)}.html"
        path.write_text(
            "<!doctype html><html><head><title>CONFIDENTIAL</title></head>"
            "<body style='font-family:sans-serif;max-width:700px;margin:2em auto'>"
            "<h2>Internal - Do Not Distribute</h2>"
            "<p>Credential rotation schedule and recovery codes attached.</p>"
            "<p>Last updated by IT Security team. This document is watermarked.</p>"
            f"<img src='{url}' width='1' height='1' alt=''>"
            "</body></html>"
        )
        print(f"Booby-trapped document written -> {path}")
        print("Opening it (in a browser/preview) loads the pixel and trips the trap.")

    elif kind == "env":
        path = DATA / f"{_safe(name)}.env"
        path.write_text(
            "# staging environment - KEEP SECRET\n"
            f"API_BASE_URL={base_url.rstrip('/')}\n"
            f"API_KEY=ct_{secrets.token_urlsafe(24)}\n"
            f"WEBHOOK_URL={url}\n"
            "DB_HOST=prod-db.internal\n"
            "DB_PORT=5432\n"
            "DB_NAME=appdb\n"
            "DB_USER=appuser\n"
            "DB_PASSWORD=" + secrets.token_urlsafe(18) + "\n"
            "REDIS_URL=redis://cache.internal:6379/0\n"
            f"SENTRY_DSN=https://ct_{secrets.token_urlsafe(12)}@sentry.io/123456\n"
        )
        print(f"Decoy .env written -> {path}")
        print("Any tool or SSRF that fetches WEBHOOK_URL or API_BASE trips the trap.")

    elif kind == "aws":
        akid = "AKIA" + "".join(
            secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16)
        )
        secret = base64.b64encode(secrets.token_bytes(30)).decode()
        path = DATA / f"{_safe(name)}.credentials"
        path.write_text(
            "[default]\n"
            f"aws_access_key_id = {akid}\n"
            f"aws_secret_access_key = {secret}\n"
            f"# provisioning endpoint: {url}\n"
            "[profile canary]\n"
            f"aws_access_key_id = {akid}\n"
            f"aws_secret_access_key = {secret}\n"
            "region = us-east-1\n"
        )
        print(f"Decoy AWS credentials written -> {path}   (key {akid})")
        print(
            "Looks realistic in a repo or config. For live AWS detection, wire this\n"
            "key's usage to CloudTrail; the callback URL also trips the local listener."
        )

    elif kind == "slack":
        # Realistic-looking Slack webhook URL embedded in a JSON config
        fake_team = secrets.token_hex(6).upper()
        fake_svc = secrets.token_hex(11)
        fake_sig = secrets.token_hex(24)
        decoy_hook = f"https://hooks.slack.com/services/T{fake_team}/B{fake_svc.upper()}/{fake_sig}"
        path = DATA / f"{_safe(name)}_slack_config.json"
        path.write_text(json.dumps({
            "description": "Internal alerting channel webhook",
            "channel": "#security-alerts",
            "webhook_url": decoy_hook,
            "canary_ping": url,
            "token": f"xoxb-{secrets.token_urlsafe(12)}-{secrets.token_urlsafe(12)}",
            "team": "yourco",
        }, indent=2))
        print(f"Decoy Slack config written -> {path}")
        print("Anyone who reads and acts on this webhook config will ping canary_ping.")

    elif kind == "apikey":
        # Generic API key file (looks like a .netrc or credentials YAML)
        key_val = "sk-" + secrets.token_urlsafe(32)
        path = DATA / f"{_safe(name)}_api_credentials.yml"
        path.write_text(
            "# API credentials - generated by deploy pipeline\n"
            f"api_key: \"{key_val}\"\n"
            f"api_secret: \"{secrets.token_urlsafe(24)}\"\n"
            "endpoint: https://api.internal.yourco.com/v2\n"
            f"callback_url: {url}\n"
            f"client_id: client_{secrets.token_hex(8)}\n"
            "environment: production\n"
        )
        print(f"Decoy API key file written -> {path}")
        print("callback_url trips the listener when an automated tool exercises the key.")

    elif kind == "ssh":
        # Decoy SSH private key - realistic PEM structure (not a real key)
        # We generate a plausible-looking but deliberately invalid key body
        fake_key_body = base64.b64encode(secrets.token_bytes(1680)).decode()
        # Wrap at 64 chars like real PEM
        lines = [fake_key_body[i:i+64] for i in range(0, len(fake_key_body), 64)]
        pem_body = "\n".join(lines)
        path = DATA / f"{_safe(name)}_id_rsa"
        path.write_text(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{pem_body}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        path.chmod(0o600)
        # Also write a companion authorized_keys comment hinting at the canary URL
        pub_path = DATA / f"{_safe(name)}_id_rsa.pub"
        fake_pubkey = base64.b64encode(secrets.token_bytes(279)).decode()
        pub_path.write_text(
            f"ssh-rsa {fake_pubkey} deploy@prod-server # verify: {url}\n"
        )
        print(f"Decoy SSH private key written -> {path}")
        print(f"Companion public key -> {pub_path}")
        print(
            "Drop the private key on a compromised host. Any automation that reads\n"
            "the pub key comment and pings the verify URL will trip the listener."
        )

    elif kind == "db":
        # Decoy database connection string and .pgpass entry
        fake_pass = secrets.token_urlsafe(18)
        path = DATA / f"{_safe(name)}.pgpass"
        path.write_text(
            "# PostgreSQL password file - format: hostname:port:database:username:password\n"
            f"prod-db.internal:5432:appdb:appuser:{fake_pass}\n"
            f"analytics-db.internal:5432:analyticsdb:reader:{secrets.token_urlsafe(14)}\n"
        )
        path.chmod(0o600)
        dsn_path = DATA / f"{_safe(name)}_dsn.conf"
        dsn_path.write_text(
            "[database]\n"
            "host     = prod-db.internal\n"
            "port     = 5432\n"
            "name     = appdb\n"
            "user     = appuser\n"
            f"password = {fake_pass}\n"
            f"# connection health check: {url}\n"
        )
        print(f"Decoy .pgpass written -> {path}")
        print(f"Decoy DSN config written -> {dsn_path}")
        print("Health-check URL in the DSN config trips the listener when fetched.")

    elif kind == "kubeconfig":
        # Decoy kubeconfig (realistic YAML structure)
        cluster_name = "prod-k8s-cluster"
        fake_cert = base64.b64encode(secrets.token_bytes(1188)).decode()
        fake_key = base64.b64encode(secrets.token_bytes(1676)).decode()
        fake_token = secrets.token_urlsafe(48)
        path = DATA / f"{_safe(name)}_kubeconfig.yaml"
        path.write_text(
            "apiVersion: v1\n"
            "kind: Config\n"
            "clusters:\n"
            f"- cluster:\n"
            f"    certificate-authority-data: {fake_cert[:40]}...\n"
            f"    server: https://k8s-api.internal.yourco.com:6443\n"
            f"    extensions:\n"
            f"    - name: canary\n"
            f"      extension:\n"
            f"        health-check: {url}\n"
            f"  name: {cluster_name}\n"
            "contexts:\n"
            "- context:\n"
            f"    cluster: {cluster_name}\n"
            "    namespace: default\n"
            "    user: admin\n"
            f"  name: {cluster_name}-context\n"
            f"current-context: {cluster_name}-context\n"
            "users:\n"
            "- name: admin\n"
            "  user:\n"
            f"    token: {fake_token}\n"
            f"    client-certificate-data: {fake_cert[:40]}...\n"
            f"    client-key-data: {fake_key[:40]}...\n"
        )
        path.chmod(0o600)
        print(f"Decoy kubeconfig written -> {path}")
        print(
            "Drop in ~/.kube/config or a repo. The cluster health-check extension\n"
            "URL trips the listener when any tooling validates connectivity."
        )


# ---------------------------------------------------------------------------
# Listener + handler
# ---------------------------------------------------------------------------
_DASHBOARD_CSS = """
<style>
  body{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:0}
  h1{font-size:1.4rem;padding:1rem 2rem;margin:0;background:#161b22;border-bottom:1px solid #30363d}
  h1 span{color:#f85149;margin-right:.5rem}
  .grid{display:flex;gap:1rem;padding:1rem 2rem;flex-wrap:wrap}
  .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem 1.5rem;min-width:140px}
  .card .val{font-size:2rem;font-weight:700;color:#58a6ff}
  .card .lbl{font-size:.8rem;color:#8b949e;margin-top:.25rem}
  table{border-collapse:collapse;width:100%;font-size:.85rem}
  th{text-align:left;padding:.5rem 1rem;background:#161b22;color:#8b949e;border-bottom:1px solid #30363d;position:sticky;top:0}
  td{padding:.45rem 1rem;border-bottom:1px solid #21262d}
  tr:hover td{background:#1c2128}
  .badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.75rem;font-weight:600}
  .ok{background:#1f6feb33;color:#58a6ff}
  .tripped{background:#f8514933;color:#f85149}
  .armed{background:#238636;color:#fff}
  .disarmed{background:#6e768180;color:#c9d1d9}
  .section{padding:1.5rem 2rem}
  .section h2{font-size:1rem;color:#8b949e;margin:0 0 .75rem;text-transform:uppercase;letter-spacing:.08em}
  footer{padding:1rem 2rem;font-size:.75rem;color:#8b949e;border-top:1px solid #21262d;margin-top:1rem}
  .pill{font-size:.7rem;padding:.1rem .4rem;border-radius:3px;background:#30363d;color:#8b949e;margin-left:.3rem}
  meta[http-equiv]{content:""}
</style>
"""


def _render_dashboard(con: sqlite3.Connection, port: int) -> str:
    """Render an HTML dashboard showing tokens and recent triggers."""
    tokens = _all_tokens(con)
    triggers = _all_triggers(con, limit=50)
    armed_count = sum(1 for t in tokens if t["active"])
    disarmed_count = len(tokens) - armed_count
    trip_count = len(_all_triggers(con))
    ips = {tr["ip"] for tr in _all_triggers(con)}

    rows_tok = ""
    for t in tokens:
        status_cls = "armed" if t["active"] else "disarmed"
        status_txt = "armed" if t["active"] else "disarmed"
        exp = t["expire_date"] or "-"
        lbl = f'<span class="pill">{t["label"]}</span>' if t["label"] else ""
        rows_tok += (
            f"<tr>"
            f"<td><code>{t['id']}</code></td>"
            f"<td><span class='badge ok'>{t['kind']}</span></td>"
            f"<td>{t['name']}{lbl}</td>"
            f"<td><span class='badge {status_cls}'>{status_txt}</span></td>"
            f"<td>{t['created']}</td>"
            f"<td>{exp}</td>"
            f"<td><a href='{t['url']}' style='color:#58a6ff'>{t['url']}</a></td>"
            f"</tr>\n"
        )

    rows_trg = ""
    for e in triggers:
        rdns_str = f" ({e['rdns']})" if e["rdns"] else ""
        ua_str = (e["ua"] or "")[:60]
        rows_trg += (
            f"<tr>"
            f"<td>{e['ts']}</td>"
            f"<td><span class='badge tripped'>{e['kind']}</span></td>"
            f"<td>{e['name']}</td>"
            f"<td>{e['ip']}{rdns_str}</td>"
            f"<td>{ua_str}</td>"
            f"</tr>\n"
        )
    if not rows_trg:
        rows_trg = "<tr><td colspan='5' style='color:#8b949e;text-align:center'>no triggers yet</td></tr>"

    return f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta http-equiv='refresh' content='10'>
<title>canarytrap dashboard</title>
{_DASHBOARD_CSS}
</head>
<body>
<h1><span>&#x1faa4;</span>canarytrap <span style='font-weight:300;font-size:.9rem;color:#8b949e'>live dashboard</span></h1>
<div class='grid'>
  <div class='card'><div class='val'>{armed_count}</div><div class='lbl'>armed tokens</div></div>
  <div class='card'><div class='val'>{disarmed_count}</div><div class='lbl'>disarmed tokens</div></div>
  <div class='card'><div class='val' style='color:#f85149'>{trip_count}</div><div class='lbl'>total trips</div></div>
  <div class='card'><div class='val' style='color:#ffa657'>{len(ips)}</div><div class='lbl'>unique source IPs</div></div>
</div>

<div class='section'>
  <h2>tokens</h2>
  <table>
    <thead><tr>
      <th>ID</th><th>kind</th><th>name</th><th>status</th>
      <th>created</th><th>expires</th><th>tripwire URL</th>
    </tr></thead>
    <tbody>{rows_tok}</tbody>
  </table>
</div>

<div class='section'>
  <h2>recent triggers (last 50)</h2>
  <table>
    <thead><tr>
      <th>time</th><th>kind</th><th>token</th><th>source IP</th><th>user-agent</th>
    </tr></thead>
    <tbody>{rows_trg}</tbody>
  </table>
</div>

<footer>
  canarytrap &nbsp;|&nbsp; port {port} &nbsp;|&nbsp;
  refreshes every 10s &nbsp;|&nbsp;
  data dir: {DATA}
</footer>
</body>
</html>"""


def make_handler(webhook: Optional[str], port: int):
    """Build and return the HTTP request handler class for the listener."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence default access log
            pass

        def do_GET(self):
            path = self.path.split("?")[0]
            if path.startswith("/t/"):
                tid = path[3:]
                self._trip(tid)
                self.send_response(200)
                self.send_header("Content-Type", "image/gif")
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                self.end_headers()
                self.wfile.write(PIXEL)
            elif path == "/" or path == "/dashboard":
                body = self._dashboard()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def _dashboard(self) -> bytes:
            try:
                con = _db()
                html = _render_dashboard(con, port)
                con.close()
                return html.encode()
            except Exception as e:
                return f"<pre>dashboard error: {e}</pre>".encode()

        def _trip(self, tid: str) -> None:
            raw_ip = self.headers.get("X-Forwarded-For", self.client_address[0])
            ip = raw_ip.split(",")[0].strip()
            ua = self.headers.get("User-Agent", "")
            ts = _now()

            # Reverse-DNS in a short-timeout thread so we don't stall the response
            rdns_result: list[str] = []

            def do_rdns():
                rdns_result.append(_rdns(ip))

            rdns_thread = threading.Thread(target=do_rdns, daemon=True)
            rdns_thread.start()

            con = _db()
            tok = _token_by_id(con, tid)
            name = tok["name"] if tok else "(unknown token)"
            kind = tok["kind"] if tok else "?"

            # Wait up to 2 seconds for rDNS
            rdns_thread.join(timeout=2)
            rdns = rdns_result[0] if rdns_result else ""

            con.execute(
                "INSERT INTO triggers (ts,token_id,name,kind,ip,rdns,ua) VALUES (?,?,?,?,?,?,?)",
                (ts, tid, name, kind, ip, rdns, ua),
            )
            con.commit()
            con.close()

            rdns_str = f" ({rdns})" if rdns else ""
            ua_short = ua[:60]

            # Terminal alert
            print(
                f"\a\033[1;91mTRIPPED\033[0m  '{name}' [{kind}]"
                f"  from \033[1;93m{ip}{rdns_str}\033[0m"
                f"  {ua_short}  @ {ts}"
            )

            # macOS desktop notification
            _notify_macos(
                f"canarytrap: TRIPPED [{kind}]",
                f"'{name}' touched from {ip}{rdns_str}",
            )

            # Webhook alert
            if webhook:
                msg = (
                    f"[canarytrap TRIPPED] '{name}' ({kind}) "
                    f"from {ip}{rdns_str} | ua: {ua[:80]} | {ts}"
                )
                _post_webhook(webhook, msg)

    return Handler


def listen(host: str, port: int, webhook: Optional[str]) -> None:
    socketserver.TCPServer.allow_reuse_address = True
    con = _db()
    n_armed = con.execute("SELECT COUNT(*) FROM tokens WHERE active=1").fetchone()[0]
    con.close()
    with socketserver.TCPServer((host, port), make_handler(webhook, port)) as srv:
        print(
            f"canarytrap listening on http://{host}:{port}  "
            f"({n_armed} tokens armed)  (Ctrl-C to stop)"
        )
        print(f"  dashboard: http://localhost:{port}/")
        print(f"  token trips: http://localhost:{port}/t/<id>")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped.")


# ---------------------------------------------------------------------------
# Disarm / revoke
# ---------------------------------------------------------------------------
def disarm(token_id: str) -> None:
    """Mark a token as inactive (revoked)."""
    con = _db()
    row = _token_by_id(con, token_id)
    if not row:
        con.close()
        sys.exit(f"token '{token_id}' not found")
    con.execute("UPDATE tokens SET active=0 WHERE id=?", (token_id,))
    con.commit()
    con.close()
    print(f"disarmed: [{row['kind']}] '{row['name']}' (id={token_id})")


# ---------------------------------------------------------------------------
# Views - tokens
# ---------------------------------------------------------------------------
def show_tokens(
    kind: Optional[str] = None,
    active_only: bool = False,
) -> None:
    con = _db()
    toks = _all_tokens(con, kind=kind, active_only=active_only)
    con.close()

    con2 = _db()
    # Build a trip-count index
    rows = con2.execute(
        "SELECT token_id, COUNT(*) as c FROM triggers GROUP BY token_id"
    ).fetchall()
    trip_counts = {r["token_id"]: r["c"] for r in rows}
    con2.close()

    console = _console()
    if console:
        from rich.table import Table
        from rich.text import Text

        t = Table(title="honeytokens", header_style="bold")
        for col in ("id", "kind", "name", "label", "status", "trips", "created", "expires", "url"):
            t.add_column(col)
        for k in toks:
            status = "armed" if k["active"] else "disarmed"
            status_txt = Text(status)
            status_txt.stylize("green" if k["active"] else "dim")
            trips = trip_counts.get(k["id"], 0)
            trips_txt = Text(str(trips))
            if trips > 0:
                trips_txt.stylize("bold red")
            t.add_row(
                k["id"], k["kind"], k["name"],
                k["label"] or "", status_txt,
                trips_txt, k["created"],
                k["expire_date"] or "-", k["url"],
            )
        console.print(t)
    else:
        header = f"{'id':<18} {'kind':<10} {'status':<10} {'trips':>5}  name"
        print(header)
        print("-" * len(header))
        for k in toks:
            status = "armed" if k["active"] else "disarmed"
            trips = trip_counts.get(k["id"], 0)
            print(f"{k['id']:<18} {k['kind']:<10} {status:<10} {trips:>5}  {k['name']}")


# ---------------------------------------------------------------------------
# Views - watch
# ---------------------------------------------------------------------------
def watch() -> None:
    console = _console()
    if not console:
        con = _db()
        for e in _all_triggers(con):
            rdns_str = f" ({e['rdns']})" if e["rdns"] else ""
            print(f"{e['ts']}  {e['name']:<20}  {e['kind']:<10}  {e['ip']}{rdns_str}  {e['ua'][:50]}")
        con.close()
        return

    from rich.table import Table
    from rich.live import Live

    def render():
        con = _db()
        all_trg = _all_triggers(con)
        recent = all_trg[:20]
        n_tok = con.execute("SELECT COUNT(*) FROM tokens WHERE active=1").fetchone()[0]
        con.close()

        title = f"canarytrap - {len(all_trg)} triggers total - {n_tok} tokens armed"
        tbl = Table(title=title, header_style="bold red")
        for col in ("time", "token", "kind", "source IP", "rDNS", "user-agent"):
            tbl.add_column(col)
        for e in recent:
            rdns = e["rdns"] or "-"
            ua = (e["ua"] or "")[:50]
            tbl.add_row(e["ts"], e["name"], e["kind"], e["ip"], rdns, ua)
        if not recent:
            tbl.add_row("-", "waiting for a bite...", "", "", "", "")
        return tbl

    with Live(render(), refresh_per_second=2, console=console) as live:
        try:
            while True:
                time.sleep(0.5)
                live.update(render())
        except KeyboardInterrupt:
            pass


# ---------------------------------------------------------------------------
# Views - triggers
# ---------------------------------------------------------------------------
def show_triggers() -> None:
    con = _db()
    rows = _all_triggers(con)
    con.close()
    out = [dict(r) for r in rows]
    print(json.dumps(out, indent=2))


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def report(html_out: Optional[str] = None) -> None:
    con = _db()
    all_trg = _all_triggers(con)
    all_tok = _all_tokens(con)
    con.close()

    total_trips = len(all_trg)
    unique_ips = {e["ip"] for e in all_trg}
    first_seen = all_trg[-1]["ts"] if all_trg else "-"
    last_seen = all_trg[0]["ts"] if all_trg else "-"

    # Top tokens by trip count
    token_hits: dict[str, int] = {}
    token_names: dict[str, str] = {}
    for e in all_trg:
        token_hits[e["token_id"]] = token_hits.get(e["token_id"], 0) + 1
        token_names[e["token_id"]] = e["name"]
    top_tokens = sorted(token_hits.items(), key=lambda x: x[1], reverse=True)[:5]

    # Trips by kind
    kind_hits: dict[str, int] = {}
    for e in all_trg:
        kind_hits[e["kind"]] = kind_hits.get(e["kind"], 0) + 1

    # Top source IPs
    ip_hits: dict[str, int] = {}
    for e in all_trg:
        ip_hits[e["ip"]] = ip_hits.get(e["ip"], 0) + 1
    top_ips = sorted(ip_hits.items(), key=lambda x: x[1], reverse=True)[:5]

    console = _console()
    if console:
        from rich.table import Table
        from rich.panel import Panel
        from rich.columns import Columns

        stats_panel = Panel(
            f"Total trips: [bold red]{total_trips}[/bold red]\n"
            f"Unique source IPs: [bold]{len(unique_ips)}[/bold]\n"
            f"Armed tokens: [bold green]{sum(1 for t in all_tok if t['active'])}[/bold green]\n"
            f"Total tokens: [bold]{len(all_tok)}[/bold]\n"
            f"First trip: {first_seen}\n"
            f"Last trip: {last_seen}",
            title="canarytrap report",
            border_style="red",
        )
        console.print(stats_panel)

        if top_tokens:
            tbl_tok = Table(title="top tokens", header_style="bold")
            tbl_tok.add_column("id")
            tbl_tok.add_column("name")
            tbl_tok.add_column("trips", justify="right")
            for tid, count in top_tokens:
                tbl_tok.add_row(tid, token_names.get(tid, "-"), str(count))
            console.print(tbl_tok)

        if top_ips:
            tbl_ip = Table(title="top source IPs", header_style="bold")
            tbl_ip.add_column("IP")
            tbl_ip.add_column("trips", justify="right")
            for ip, count in top_ips:
                tbl_ip.add_row(ip, str(count))
            console.print(tbl_ip)

        if kind_hits:
            tbl_k = Table(title="trips by token kind", header_style="bold")
            tbl_k.add_column("kind")
            tbl_k.add_column("trips", justify="right")
            for kind, count in sorted(kind_hits.items(), key=lambda x: x[1], reverse=True):
                tbl_k.add_row(kind, str(count))
            console.print(tbl_k)
    else:
        print(f"Total trips:       {total_trips}")
        print(f"Unique source IPs: {len(unique_ips)}")
        print(f"Armed tokens:      {sum(1 for t in all_tok if t['active'])}")
        print(f"Total tokens:      {len(all_tok)}")
        print(f"First trip:        {first_seen}")
        print(f"Last trip:         {last_seen}")
        if top_tokens:
            print("\nTop tokens:")
            for tid, count in top_tokens:
                print(f"  {tid}  {token_names.get(tid,'-')}  {count} trips")
        if top_ips:
            print("\nTop source IPs:")
            for ip, count in top_ips:
                print(f"  {ip}  {count} trips")
        if kind_hits:
            print("\nTrips by kind:")
            for k, c in sorted(kind_hits.items(), key=lambda x: x[1], reverse=True):
                print(f"  {k}  {c} trips")

    if html_out:
        _export_html_report(
            html_out, total_trips, unique_ips, first_seen, last_seen,
            top_tokens, token_names, top_ips, kind_hits, all_tok, all_trg,
        )
        print(f"\nHTML report written -> {html_out}")


def _export_html_report(
    path: str,
    total_trips: int,
    unique_ips: set,
    first_seen: str,
    last_seen: str,
    top_tokens: list,
    token_names: dict,
    top_ips: list,
    kind_hits: dict,
    all_tok: list,
    all_trg: list,
) -> None:
    rows_top_tok = ""
    for tid, count in top_tokens:
        rows_top_tok += f"<tr><td><code>{tid}</code></td><td>{token_names.get(tid,'-')}</td><td>{count}</td></tr>\n"
    rows_top_ip = ""
    for ip, count in top_ips:
        rows_top_ip += f"<tr><td>{ip}</td><td>{count}</td></tr>\n"
    rows_kind = ""
    for k, c in sorted(kind_hits.items(), key=lambda x: x[1], reverse=True):
        rows_kind += f"<tr><td>{k}</td><td>{c}</td></tr>\n"
    rows_trg = ""
    for e in all_trg[:100]:
        # sqlite3.Row does not support .get(); index by key directly with fallback
        rdns_val = e["rdns"] if e["rdns"] else ""
        rdns_str = f" ({rdns_val})" if rdns_val else ""
        ua_val = e["ua"] if e["ua"] else ""
        rows_trg += (
            f"<tr><td>{e['ts']}</td><td>{e['name']}</td><td>{e['kind']}</td>"
            f"<td>{e['ip']}{rdns_str}</td><td>{ua_val[:60]}</td></tr>\n"
        )

    html = f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<title>canarytrap report</title>
{_DASHBOARD_CSS}
</head>
<body>
<h1><span>&#x1faa4;</span>canarytrap report</h1>
<div class='grid'>
  <div class='card'><div class='val' style='color:#f85149'>{total_trips}</div><div class='lbl'>total trips</div></div>
  <div class='card'><div class='val'>{len(unique_ips)}</div><div class='lbl'>unique source IPs</div></div>
  <div class='card'><div class='val' style='color:#58a6ff'>{len(all_tok)}</div><div class='lbl'>total tokens</div></div>
  <div class='card'><div class='val'>{first_seen}</div><div class='lbl'>first trip</div></div>
  <div class='card'><div class='val'>{last_seen}</div><div class='lbl'>last trip</div></div>
</div>

<div class='section'>
  <h2>top tokens</h2>
  <table><thead><tr><th>ID</th><th>name</th><th>trips</th></tr></thead>
  <tbody>{rows_top_tok or "<tr><td colspan='3'>none</td></tr>"}</tbody></table>
</div>

<div class='section'>
  <h2>top source IPs</h2>
  <table><thead><tr><th>IP</th><th>trips</th></tr></thead>
  <tbody>{rows_top_ip or "<tr><td colspan='2'>none</td></tr>"}</tbody></table>
</div>

<div class='section'>
  <h2>trips by token kind</h2>
  <table><thead><tr><th>kind</th><th>trips</th></tr></thead>
  <tbody>{rows_kind or "<tr><td colspan='2'>none</td></tr>"}</tbody></table>
</div>

<div class='section'>
  <h2>trigger log (last 100)</h2>
  <table>
    <thead><tr><th>time</th><th>token</th><th>kind</th><th>source IP</th><th>user-agent</th></tr></thead>
    <tbody>{rows_trg or "<tr><td colspan='5'>no triggers</td></tr>"}</tbody>
  </table>
</div>

<footer>generated by canarytrap - {_now()}</footer>
</body>
</html>"""
    Path(path).write_text(html)


# ---------------------------------------------------------------------------
# Export (SIEM)
# ---------------------------------------------------------------------------
def export_data(fmt: str) -> None:
    con = _db()
    all_trg = _all_triggers(con)
    con.close()

    records = [dict(r) for r in all_trg]

    if fmt == "json":
        print(json.dumps(records, indent=2))

    elif fmt == "csv":
        if not records:
            print("token_id,name,kind,ts,ip,rdns,ua")
            return
        out = io.StringIO()
        w = csv.DictWriter(out, fieldnames=list(records[0].keys()))
        w.writeheader()
        w.writerows(records)
        print(out.getvalue(), end="")

    elif fmt == "cef":
        # CEF (Common Event Format) for SIEM ingestion
        for r in records:
            ua_ext = (r.get("ua") or "").replace("=", "\\=").replace("|", "\\|")
            name_ext = (r.get("name") or "").replace("=", "\\=").replace("|", "\\|")
            rdns_ext = (r.get("rdns") or "").replace("=", "\\=").replace("|", "\\|")
            print(
                f"CEF:0|canarytrap|HoneyToken|1.0|TRIP|CanaryToken tripped|7|"
                f"src={r.get('ip','')} "
                f"shost={rdns_ext} "
                f"rt={r.get('ts','')} "
                f"cs1={r.get('token_id','')} "
                f"cs1Label=tokenId "
                f"cs2={r.get('kind','')} "
                f"cs2Label=tokenKind "
                f"cs3={name_ext} "
                f"cs3Label=tokenName "
                f"requestClientApplication={ua_ext}"
            )
    else:
        sys.exit(f"unknown format '{fmt}'. Choose: json, csv, cef")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    p = argparse.ArgumentParser(
        prog="canarytrap",
        description="Mint honeytokens and get alerted the instant an intruder touches one.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # mint
    m = sub.add_parser("mint", help="create a honeytoken")
    m.add_argument("kind", choices=list(VALID_KINDS))
    m.add_argument("--name", required=True, help="human-readable token name")
    m.add_argument("--url", default="http://localhost:8000",
                   help="public base URL of your listener (default: http://localhost:8000)")
    m.add_argument("--label", default=None, help="optional label/tag for the token")
    m.add_argument("--expire", type=int, default=None, metavar="DAYS",
                   help="auto-expire after this many days (informational)")

    # listen
    li = sub.add_parser("listen", help="run the trap listener and live dashboard")
    li.add_argument("--host", default="0.0.0.0")
    li.add_argument("--port", type=int, default=8000)
    li.add_argument("--webhook", default=None,
                    help="Slack or Discord webhook URL for trip alerts")

    # tokens
    tk = sub.add_parser("tokens", help="list honeytokens")
    tk.add_argument("--kind", default=None, choices=list(VALID_KINDS),
                    help="filter by token kind")
    tk.add_argument("--active", action="store_true",
                    help="show only armed (active) tokens")

    # watch
    sub.add_parser("watch", help="live trigger feed (refreshes every 0.5s)")

    # triggers
    sub.add_parser("triggers", help="dump raw trigger log as JSON")

    # report
    rp = sub.add_parser("report", help="statistics report")
    rp.add_argument("--html", default=None, metavar="FILE",
                    help="also export an HTML report to FILE")

    # export
    ex = sub.add_parser("export", help="export trigger log for SIEM ingestion")
    ex.add_argument("--format", default="json", choices=["json", "csv", "cef"],
                    help="output format: json (default), csv, or cef")

    # disarm
    da = sub.add_parser("disarm", help="revoke/disarm a token by ID")
    da.add_argument("id", help="token ID to disarm")

    args = p.parse_args(argv)

    if args.cmd == "mint":
        mint(args.kind, args.name, args.url, label=args.label, expire_days=args.expire)
    elif args.cmd == "listen":
        listen(args.host, args.port, args.webhook)
    elif args.cmd == "tokens":
        show_tokens(kind=args.kind, active_only=args.active)
    elif args.cmd == "watch":
        watch()
    elif args.cmd == "triggers":
        show_triggers()
    elif args.cmd == "report":
        report(html_out=args.html)
    elif args.cmd == "export":
        export_data(args.format)
    elif args.cmd == "disarm":
        disarm(args.id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
