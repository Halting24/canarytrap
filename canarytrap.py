#!/usr/bin/env python3
"""
canarytrap - deception engineering in a single file.

Mint believable *honeytokens* (decoy AWS keys, a fake .env, tripwire URLs, a
booby-trapped document with a tracking pixel), drop them where an intruder will
find them, then run the listener. The moment a token is touched you get an
instant alert with the attacker's IP, user-agent and timestamp - early-warning
that someone is already inside, with near-zero false positives.

    canarytrap mint url   --name "prod-backup-link"
    canarytrap mint doc   --name "Q3_passwords"      # HTML w/ tracking pixel
    canarytrap mint env   --name "staging-.env"
    canarytrap mint aws   --name "ci-deploy-key"
    canarytrap listen     --port 8000                # start the trap
    canarytrap watch                                 # live trigger dashboard

Self-contained demo: tokens point at http://localhost:8000 by default. For real
use, run `listen` on a host an attacker can reach (or behind a tunnel) and pass
--url https://your-canary-host.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import http.server
import json
import os
import secrets
import socketserver
import sys
import uuid
from pathlib import Path

DATA = Path(os.environ.get("CANARYTRAP_DATA", Path.cwd() / "canarytrap_data"))
TOKENS = DATA / "tokens.json"
TRIGGERS = DATA / "triggers.json"
PIXEL = base64.b64decode(  # 1x1 transparent gif
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")


def _load(p: Path) -> list:
    return json.loads(p.read_text()) if p.exists() else []


def _save(p: Path, data) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2))


def _now() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Mint
# --------------------------------------------------------------------------- #
def mint(kind: str, name: str, base_url: str) -> dict:
    tok = {"id": uuid.uuid4().hex[:16], "kind": kind, "name": name,
           "created": _now()}
    url = f"{base_url.rstrip('/')}/t/{tok['id']}"
    tok["url"] = url
    tokens = _load(TOKENS)
    tokens.append(tok)
    _save(TOKENS, tokens)

    print(f"🪤  minted [{kind}] '{name}'  id={tok['id']}")
    print(f"    tripwire: {url}\n")

    if kind == "url":
        print("Drop this link somewhere tempting (a bookmark, a README, a Slack pin):")
        print(f"    {url}")
    elif kind == "doc":
        path = DATA / f"{_safe(name)}.html"
        path.write_text(
            "<!doctype html><html><head><title>CONFIDENTIAL</title></head>"
            "<body style='font-family:sans-serif'>"
            "<h2>Internal - Do Not Distribute</h2>"
            "<p>Credential rotation schedule &amp; recovery codes attached.</p>"
            f"<img src='{url}' width='1' height='1' alt=''></body></html>")
        print(f"Booby-trapped document written -> {path}")
        print("Opening it (in a browser/preview) loads the pixel and trips the trap.")
    elif kind == "env":
        path = DATA / f"{_safe(name)}.env"
        path.write_text(
            "# staging environment - KEEP SECRET\n"
            f"API_BASE_URL={base_url.rstrip('/')}\n"
            f"API_KEY=ct_{secrets.token_urlsafe(24)}\n"
            f"WEBHOOK_URL={url}\n"
            "DB_PASSWORD=" + secrets.token_urlsafe(18) + "\n")
        print(f"Decoy .env written -> {path}")
        print("Any tool/SSRF that fetches WEBHOOK_URL or API_BASE trips the trap.")
    elif kind == "aws":
        akid = "AKIA" + "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
                                 for _ in range(16))
        path = DATA / f"{_safe(name)}.credentials"
        path.write_text(
            "[default]\n"
            f"aws_access_key_id = {akid}\n"
            f"aws_secret_access_key = {base64.b64encode(secrets.token_bytes(30)).decode()}\n"
            f"# provisioning callback: {url}\n")
        print(f"Decoy AWS credentials written -> {path}   (key {akid})")
        print("Looks real in a repo/config. For live AWS detection, wire this key's"
              "\nusage to CloudTrail; the callback URL also trips the local listener.")
    else:
        sys.exit("kind must be one of: url, doc, env, aws")
    return tok


def _safe(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)


# --------------------------------------------------------------------------- #
# Listener
# --------------------------------------------------------------------------- #
def make_handler(webhook: str | None):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence default logging
            pass

        def do_GET(self):
            if self.path.startswith("/t/"):
                tid = self.path.split("/t/", 1)[1].split("?")[0]
                self._trip(tid)
                self.send_response(200)
                self.send_header("Content-Type", "image/gif")
                self.end_headers()
                self.wfile.write(PIXEL)
            else:
                self.send_response(404); self.end_headers()

        def _trip(self, tid: str):
            tokens = {t["id"]: t for t in _load(TOKENS)}
            tok = tokens.get(tid)
            name = tok["name"] if tok else "(unknown token)"
            kind = tok["kind"] if tok else "?"
            ip = self.headers.get("X-Forwarded-For", self.client_address[0])
            ua = self.headers.get("User-Agent", "")
            evt = {"ts": _now(), "id": tid, "name": name, "kind": kind,
                   "ip": ip, "ua": ua}
            trg = _load(TRIGGERS); trg.append(evt); _save(TRIGGERS, trg)
            print(f"\a🚨 \033[1;91mTRIPPED\033[0m  '{name}' [{kind}]  from "
                  f"\033[1;93m{ip}\033[0m  {ua[:50]}  @ {evt['ts']}")
            if webhook:
                _post(webhook, f"🚨 canarytrap: '{name}' ({kind}) tripped from {ip}")
    return Handler


def _post(url: str, text: str):
    try:
        import urllib.request
        body = json.dumps({"content": text, "text": text}).encode()
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"   (webhook failed: {e})")


def listen(host: str, port: int, webhook: str | None):
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((host, port), make_handler(webhook)) as srv:
        print(f"👂 canarytrap listening on http://{host}:{port}  "
              f"({len(_load(TOKENS))} tokens armed)  (Ctrl-C to stop)")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped.")


# --------------------------------------------------------------------------- #
# Views
# --------------------------------------------------------------------------- #
def _console():
    try:
        from rich.console import Console
        return Console()
    except ImportError:
        return None


def show_tokens():
    toks = _load(TOKENS)
    con = _console()
    if con:
        from rich.table import Table
        t = Table(title="armed honeytokens", header_style="bold")
        for c in ("id", "kind", "name", "created", "url"):
            t.add_column(c)
        for k in toks:
            t.add_row(k["id"], k["kind"], k["name"], k["created"], k["url"])
        con.print(t)
    else:
        for k in toks:
            print(k)


def watch():
    con = _console()
    if not con:
        for e in _load(TRIGGERS):
            print(e)
        return
    from rich.table import Table
    from rich.live import Live
    import time

    def render():
        trg = _load(TRIGGERS)[-20:]
        t = Table(title=f"🪤 canarytrap - {len(_load(TRIGGERS))} triggers "
                        f"· {len(_load(TOKENS))} tokens armed", header_style="bold red")
        for c in ("time", "token", "kind", "source IP", "user-agent"):
            t.add_column(c)
        for e in reversed(trg):
            t.add_row(e["ts"], e["name"], e["kind"], e["ip"], e["ua"][:40])
        if not trg:
            t.add_row(" - ", "waiting for a bite…", "", "", "")
        return t

    with Live(render(), refresh_per_second=2, console=con) as live:
        try:
            while True:
                time.sleep(0.5); live.update(render())
        except KeyboardInterrupt:
            pass


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None):
    p = argparse.ArgumentParser(prog="canarytrap",
                                description="Mint honeytokens and get alerted when they're touched.")
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("mint", help="create a honeytoken")
    m.add_argument("kind", choices=["url", "doc", "env", "aws"])
    m.add_argument("--name", required=True)
    m.add_argument("--url", default="http://localhost:8000", help="public base URL of your listener")

    l = sub.add_parser("listen", help="run the trap listener")
    l.add_argument("--host", default="0.0.0.0")
    l.add_argument("--port", type=int, default=8000)
    l.add_argument("--webhook", help="Slack/Discord webhook for alerts")

    sub.add_parser("tokens", help="list armed tokens")
    sub.add_parser("watch", help="live trigger dashboard")
    tr = sub.add_parser("triggers", help="dump raw trigger log")

    args = p.parse_args(argv)
    if args.cmd == "mint":
        mint(args.kind, args.name, args.url)
    elif args.cmd == "listen":
        listen(args.host, args.port, args.webhook)
    elif args.cmd == "tokens":
        show_tokens()
    elif args.cmd == "watch":
        watch()
    elif args.cmd == "triggers":
        print(json.dumps(_load(TRIGGERS), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
