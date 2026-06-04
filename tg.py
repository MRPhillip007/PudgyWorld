#!/usr/bin/env python3
"""
Tiny Telegram notifier with edit-in-place support.

Usage:
    import tg
    mid = tg.send("hello")           # returns message_id (or None on failure)
    tg.edit(mid, "hello, updated")   # edits that same message

All calls are best-effort — failures are logged but never raised, so the
caller's main flow is never blocked by a flaky network or Telegram throttle.
"""

from __future__ import annotations

import json
import queue
import ssl
import threading
import time
import urllib.parse
import urllib.request

BOT_TOKEN = "8991199892:AAFUWF35cOw-FMWLTOdNVkR2x44cNTu5ZMg"
CHAT_ID   = "769594408"

# Skip TLS verification for the Telegram call only — needed behind some
# corporate proxies / self-signed roots. We're only sending notifications,
# no sensitive data flows back.
_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode    = ssl.CERT_NONE


def _api(method: str, payload: dict, timeout: float = 5.0) -> dict | None:
    """POST a Telegram bot API call. Returns the parsed `result` dict or
    None on any failure."""
    if not BOT_TOKEN or not CHAT_ID:
        return None
    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{BOT_TOKEN}/{method}",
            data=urllib.parse.urlencode(payload).encode(),
        )
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            data = json.loads(r.read().decode())
        if not data.get("ok"):
            print(f"[tg] {method} not ok: {data}", flush=True)
            return None
        return data.get("result")
    except Exception as e:
        print(f"[tg] {method} failed: {e!r}", flush=True)
        return None


def send(text: str) -> int | None:
    """Send a fresh message. Returns the message_id for later editing."""
    res = _api("sendMessage", {"chat_id": CHAT_ID, "text": text})
    if not res:
        return None
    return res.get("message_id")


# Per-message-id serialized edit queues so edits arrive in order without
# blocking the caller. Each message id gets its own worker thread.
_edit_queues: dict[int, queue.Queue[str | None]] = {}
_edit_lock = threading.Lock()


def _edit_worker(message_id: int, q: "queue.Queue[str | None]") -> None:
    last_text: str | None = None
    while True:
        text = q.get()
        if text is None:                  # sentinel: shut down
            return
        # Coalesce: skip identical consecutive edits (Telegram rejects them
        # with "message is not modified" anyway).
        if text == last_text:
            continue
        _api("editMessageText", {
            "chat_id":    CHAT_ID,
            "message_id": message_id,
            "text":       text,
        })
        last_text = text
        # Telegram rate limit: 1 edit/sec per message is the documented
        # safe rate. We respect it so a burst of step updates doesn't get
        # 429'd.
        time.sleep(1.0)


def edit(message_id: int | None, text: str) -> None:
    """Queue an edit to `message_id`. Returns immediately — actual HTTP
    happens in a background thread, in-order, max ~1 edit/sec."""
    if message_id is None:
        return
    with _edit_lock:
        q = _edit_queues.get(message_id)
        if q is None:
            q = queue.Queue()
            _edit_queues[message_id] = q
            t = threading.Thread(target=_edit_worker,
                                 args=(message_id, q),
                                 daemon=True)
            t.start()
    q.put(text)


def flush(message_id: int | None, timeout: float = 10.0) -> None:
    """Wait for all queued edits for this message_id to actually be sent.
    Call once at the end of a tutorial to make sure the final state shows
    up before the next account begins."""
    if message_id is None:
        return
    with _edit_lock:
        q = _edit_queues.get(message_id)
    if q is None:
        return
    deadline = time.time() + timeout
    while q.qsize() > 0 and time.time() < deadline:
        time.sleep(0.2)
