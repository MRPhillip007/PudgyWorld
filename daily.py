#!/usr/bin/env python3
"""
Daily reward collector — runs forever as a background service.

For every tutorial-completed account in accounts.json, one thread does:
  1) refresh the JWT if expired / near expiry (jwtharvest)
  2) open a WS via that account's proxy_raw
  3) send {"action":"login"}
  4) send {"action":"collectDailyReward"}, wait for dailyRewardCollected
  5) close the WS
  6) sleep ~24h (with light jitter so accounts drift apart over time)
  7) goto 1

All traffic for an account goes through that account's pinned proxy. Per-day
failures are non-fatal — that account just retries on the next 24h cycle.

Usage:
  python daily.py
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import random
import re
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
import websocket
from datetime import datetime, timezone
from pathlib import Path

import jwtharvest
jwtharvest.VERBOSE = False
import tg

# ===================== CONFIG =====================
KEY      = b"wB7FLqHISDjBxCaklTFafvUpacahD5ocMORUkR+PpJI="
WS_URL   = "wss://pudgyworld.pudgyworld.com/ws?ver=0.8.4&g=1"
ORIGIN   = "https://play.pudgyworld.com"
ACCOUNTS_FILE = "accounts.json"

# How long between collection cycles for the same account. 24h with a small
# random jitter so all accounts don't fire at the same wall-clock instant
# every day (and so a once-a-day pattern looks slightly more human).
DAILY_INTERVAL_SEC = 24 * 3600
DAILY_JITTER_SEC   = 300         # ±5 min

# Stagger account startups so we don't fire N WS handshakes at once.
STARTUP_STAGGER_SEC = 0.5

# Retry tuning for a single attempt failure (network, proxy, transient
# server hiccup). Logical server errors ("AlreadyCollected" etc.) do NOT
# retry — there's no point — we just wait for the next 24h cycle.
RETRY_DELAY_MIN_SEC     = 30
RETRY_DELAY_MAX_SEC     = 90
MAX_RETRIES_PER_DAY     = 5

# WS handshake + per-frame recv timeouts.
WS_CONNECT_TIMEOUT_SEC  = 15
RECV_TIMEOUT_SEC        = 20

_accounts_lock = threading.Lock()


# ===================== SIGNING =====================
def sign(payload: dict) -> str:
    """Same canonical sign as exploit/orchestrator: ms-precision time + sorted
    JSON + HMAC-SHA256 base64. Adds time + sig to payload, returns JSON to send."""
    now = datetime.now(timezone.utc)
    payload["time"] = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    canon = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload["sig"] = base64.b64encode(
        hmac.new(KEY, canon.encode(), hashlib.sha256).digest()
    ).decode()
    return json.dumps(payload, sort_keys=True)


# ===================== PROXY-AWARE WS =====================
def _ws_connect(jwt: str, proxy_url: str | None) -> websocket.WebSocket:
    """Open the WS, optionally routed through `proxy_url`
    (requests-style http://user:pass@host:port)."""
    kwargs = dict(
        subprotocols=["pudgyprot", jwt],
        origin=ORIGIN,
        timeout=WS_CONNECT_TIMEOUT_SEC,
        enable_multithread=True,
    )
    if proxy_url:
        m = re.match(r"^(https?)://(?:([^:]+):([^@]+)@)?([^:/]+):(\d+)$", proxy_url)
        if not m:
            raise RuntimeError(f"bad proxy url for websocket: {proxy_url!r}")
        scheme, user, pw, host, port = (
            m.group(1), m.group(2), m.group(3), m.group(4), int(m.group(5))
        )
        kwargs["http_proxy_host"] = host
        kwargs["http_proxy_port"] = port
        kwargs["proxy_type"]      = scheme
        if user:
            kwargs["http_proxy_auth"] = (user, pw)
    return websocket.create_connection(WS_URL, **kwargs)


def _mask_proxy(p: str | None) -> str:
    if not p:
        return "none"
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", p)


# ===================== ACCOUNTS.JSON I/O =====================
def _load_accounts() -> list[dict]:
    p = Path(ACCOUNTS_FILE)
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8")) or []
    except (json.JSONDecodeError, ValueError):
        return []


def _save_accounts(accs: list[dict]) -> None:
    with _accounts_lock:
        Path(ACCOUNTS_FILE).write_text(
            json.dumps(accs, indent=2), encoding="utf-8"
        )


# ===================== WS HELPERS =====================
def _recv_until(ws, name: str) -> dict:
    """Read frames until one with `_action == name` arrives. Raises on a
    server errorCode frame so the caller can decide whether to retry."""
    while True:
        raw = ws.recv()
        if not raw:
            continue
        try:
            j = json.loads(raw)
        except Exception:
            continue
        if "errorCode" in j:
            raise ServerRejected(j["errorCode"].get("id", "?"))
        if j.get("_action") == name:
            return j


class ServerRejected(RuntimeError):
    """The server rejected a request with a typed errorCode. Distinct from
    network/transport failures because logical rejects (e.g. already
    collected) shouldn't be retried within the same day."""
    def __init__(self, error_id: str):
        super().__init__(f"server error: {error_id}")
        self.error_id = error_id


# ===================== ONE COLLECTION ATTEMPT =====================
def collect_one(account: dict, log) -> list[dict]:
    """One full collection attempt for one account.
    Returns the rewards list on success; raises on any failure.
    Refreshes the JWT in place; the caller is responsible for saving the
    accounts.json snapshot once it succeeds."""
    label = account["label"]
    proxy = account.get("proxy_raw")
    log(f"opening WS (proxy={_mask_proxy(proxy)})")

    # Refresh JWT if expired / near expiry. ensure_fresh_token decides.
    jwt = jwtharvest.ensure_fresh_token(label)
    account["access_token"]      = jwt
    account["access_expires_at"] = jwtharvest._decode_jwt_exp(jwt)

    ws = _ws_connect(jwt, proxy)
    ws.settimeout(RECV_TIMEOUT_SEC)
    try:
        # Login (required before any other action).
        ws.send(sign({"action": "login", "reqMsgID": 1, "serverAck": 0}))
        _recv_until(ws, "loginResponse")

        # Collect daily reward.
        ws.send(sign({
            "action":    "collectDailyReward",
            "reqMsgID":  1,
            "serverAck": 0,
        }))
        resp = _recv_until(ws, "dailyRewardCollected")

        rewards = resp.get("rewards", []) or []
        log(f"✅ collected dailyReward={resp.get('dailyReward')}  rewards={rewards}")
        return rewards
    finally:
        try: ws.close()
        except Exception: pass


# ===================== PER-ACCOUNT WORKER =====================
def worker(account: dict, all_accounts: list[dict]) -> None:
    """Forever: collect daily reward → sleep ~24h → repeat. One thread per
    account. Failures within a day are retried up to MAX_RETRIES_PER_DAY,
    then we give up and wait for the next 24h window."""
    label = account["label"]
    def log(msg: str) -> None:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] [{label}] {msg}", flush=True)

    while True:
        success     = False
        last_error  = None
        for attempt in range(1, MAX_RETRIES_PER_DAY + 1):
            try:
                collect_one(account, log)
                _save_accounts(all_accounts)   # persist refreshed JWT
                success = True
                break
            except ServerRejected as e:
                # Server logically refused (e.g. already collected today).
                # No point retrying — wait for the next 24h cycle.
                last_error = e
                log(f"⏭  server refused ({e.error_id}); waiting until next cycle")
                break
            except Exception as e:
                last_error = e
                log(f"❌ attempt {attempt}/{MAX_RETRIES_PER_DAY} failed: {e!r}")
                if attempt < MAX_RETRIES_PER_DAY:
                    delay = random.uniform(RETRY_DELAY_MIN_SEC, RETRY_DELAY_MAX_SEC)
                    log(f"   .. retrying in {delay:.0f}s")
                    time.sleep(delay)

        if not success and last_error is not None and not isinstance(last_error, ServerRejected):
            # Only TG-alert on hard failures — server-refused (already
            # collected) is the expected path on the second invocation of
            # the day and shouldn't spam.
            tg.send(
                f"⛔ [{label}] daily reward failed after "
                f"{MAX_RETRIES_PER_DAY} retries: {last_error!r}"
            )

        sleep_for = DAILY_INTERVAL_SEC + random.uniform(-DAILY_JITTER_SEC, DAILY_JITTER_SEC)
        log(f"💤 sleeping {sleep_for / 3600:.2f}h until next attempt")
        time.sleep(sleep_for)


# ===================== MAIN =====================
def main():
    accs = _load_accounts()
    if not accs:
        print(f"!! {ACCOUNTS_FILE} is empty or missing"); sys.exit(1)

    ready   = [a for a in accs if a.get("tutorial_completed")]
    skipped = [a for a in accs if not a.get("tutorial_completed")]
    if skipped:
        print(f">> skipping {len(skipped)} account(s) pending tutorial: "
              f"{[a.get('label') for a in skipped][:10]}"
              f"{'...' if len(skipped) > 10 else ''}", flush=True)
    if not ready:
        print(">> no tutorial-completed accounts; nothing to do")
        sys.exit(0)

    print(f"▶ daily-reward service: {len(ready)} account(s)", flush=True)
    tg.send(f"🎁 Daily reward service started — {len(ready)} account(s)")

    # One daemon thread per account. STARTUP_STAGGER_SEC keeps the initial
    # WS handshake burst spread out.
    for a in ready:
        t = threading.Thread(target=worker, args=(a, accs), daemon=True)
        t.start()
        time.sleep(STARTUP_STAGGER_SEC)

    # Idle main thread; everything happens in workers.
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n▶ daily-reward service stopped by user", flush=True)
        tg.send("🛑 Daily reward service stopped")
        time.sleep(1.0)


if __name__ == "__main__":
    main()
