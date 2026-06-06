#!/usr/bin/env python3
"""
Tutorial automation for freshly-registered Pudgy World accounts.

Two entry points:
  - Library:  from tutorial import run_tutorial
              run_tutorial(account_dict, proxy_url=None)
              On success, sets account['tutorial_completed'] = True and
              account['penguin_name'] = <name>.
  - CLI:      python tutorial.py            # scan accounts.json, run tutorial
                                            # for every account where
                                            # tutorial_completed != true
              python tutorial.py auto_0042  # run for a specific label only

The tutorial script (steps + payload templates) is parsed from Tutorial.txt
once at import time. Between every step from #2 onwards a random number (0-15)
of slide actions is interleaved so the timing pattern looks human.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import random
import re
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import websocket   # pip install websocket-client

import jwtharvest
import tg

# ---------- CONFIG ----------
KEY              = b"wB7FLqHISDjBxCaklTFafvUpacahD5ocMORUkR+PpJI="
WS_URL           = "wss://pudgyworld.pudgyworld.com/ws?ver=0.8.4&g=1"
ORIGIN           = "https://play.pudgyworld.com"
TUTORIAL_FILE    = "Tutorial.txt"
NAMES_FILE       = "names.txt"
ACCOUNTS_FILE    = "accounts.json"
TUTORIAL_CONCURRENCY = 20

# Per-step pacing (seconds). Real humans don't fire actions at fixed cadence.
STEP_PAUSE_MIN   = 0.5
STEP_PAUSE_MAX   = 2.5
SLIDE_PAUSE_MIN  = 0.6
SLIDE_PAUSE_MAX  = 1.8

# Two slide regimes:
#  * Small bursts BETWEEN tutorial steps — adds natural-looking movement
#    to the server's log. Kept tiny so a slide-induced disconnect doesn't
#    overlap with a state change. Skipped before high-risk actions (see
#    SLIDE_BLOCKED_BEFORE).
#  * One bigger flurry at the END, after every state change is committed.
SLIDE_BETWEEN_MIN      = 0
SLIDE_BETWEEN_MAX      = 2
SLIDE_FINAL_COUNT_MIN  = 6
SLIDE_FINAL_COUNT_MAX  = 12
SLIDE_AMOUNT_MIN       = 5
SLIDE_AMOUNT_MAX       = 30

# Don't insert slides *immediately before* these actions — a slide-caused
# disconnect right before them is the exact corruption case we want to avoid.
SLIDE_BLOCKED_BEFORE   = {"pickupSecret", "crackEgg",
                          # never inject a slide right before a fishing step —
                          # a slide-induced disconnect would tear down an
                          # active Bonko bite mid-fight.
                          "startFishing", "fishEscaped", "fishCaught"}

# Actions to skip entirely when replaying. `metric` USED to be here because
# the recorded payloads embed the original account's player_id/session_id;
# we now rewrite those at send time (see _play_tutorial's metric branch)
# so metrics are replayed safely. Add action names here to suppress them.
SKIP_ACTIONS: set[str] = set()

# Server-acknowledged receive window. Don't wait too long; tutorial server
# replies are fast and silence usually means the action was accepted.
RECV_TIMEOUT_SEC = 4

# Reconnect tuning. If the WS drops mid-tutorial, we re-handshake and continue
# from the same step. `completeTutorialStep` is idempotent server-side, so
# retrying is safe.
RECONNECT_MAX_ATTEMPTS = 3
RECONNECT_BACKOFF_SEC  = [2, 5, 10]
# Initial session boot — flaky proxies sometimes deny the very first WS
# handshake even though the next attempt succeeds. Retry the whole open-
# socket + login dance before giving up.
SESSION_BOOT_MAX_ATTEMPTS = 5
SESSION_BOOT_BACKOFF_SEC  = [2, 5, 10, 20, 30]

# At-least-once per-step delivery. Each scripted step is (re)sent until it
# lands on a socket that survives the confirm window. A proxy death during
# the send OR the confirm no longer silently drops a step — which previously
# could strand a quest even though "all 203 steps ran". Duplicate re-sends
# are safe: idempotent server actions return an "already applied" error,
# which we treat as success (see BENIGN_ERROR_SUBSTRINGS).
MAX_STEP_ATTEMPTS = 8
# Substrings in a server errorCode id that mean "this step already took
# effect" — counted as success, never retried.
BENIGN_ERROR_SUBSTRINGS = (
    "AlreadyExists", "AlreadyCollected", "AlreadyClaimed", "AlreadyOwned",
    "AlreadyComplete", "AlreadySeen",
)

# Final settle window after the last tutorial action. Server may still be
# persisting state when we close; without this, the very last steps
# (including `completeTutorial`) can be dropped.
FINAL_DRAIN_SEC = 5.0

# Post-tutorial fishing. The tutorial ends by asking the account to land a
# number of fish. Fishing is interactive (startFishing -> fishBite ->
# fishCaught -> fishRewarded) and fishCaught needs the fishId the server
# hands back in fishBite, so it can't be replayed from Tutorial.txt — we
# drive it here, mirroring orchestrator.py's FisherWorker loop. IDs below
# match orchestrator.py.
HOLE_ID            = 11
BAIT_ID            = 1
BAIT_STORE_ITEM_ID = 18
BAIT_CURRENCY_ID   = 1
BAIT_PER_PACK      = 5
# Fishing is invoked inline from Tutorial.txt via `_fish` directives, e.g.
#   {"action":"_fish","count":6,"packs":"1-2"}
# placed wherever the tutorial requires fishing — any number of times.
# `count`  = fish to land. `packs` (optional) = bait packs to buy first:
#   omitted -> ceil(count / BAIT_PER_PACK)   (always enough bait)
#   int     -> exactly that many packs
#   "a-b"   -> random.randint(a, b) packs

_state_lock = threading.Lock()


# ---------- SIGNING ----------
def sign(payload: dict) -> str:
    """Same canonicalization as exploit.py: ms-precision time + sorted-keys
    JSON + HMAC-SHA256 base64. The sig is added to the payload, then the
    payload is JSON-serialized one more time (sorted keys) for sending."""
    now = datetime.now(timezone.utc)
    payload["time"] = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    canon = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload["sig"] = base64.b64encode(
        hmac.new(KEY, canon.encode(), hashlib.sha256).digest()
    ).decode()
    return json.dumps(payload, sort_keys=True)


# ---------- TUTORIAL SCRIPT PARSING ----------
def _strip_volatile(payload: dict) -> dict:
    """Remove time + sig + reqMsgID + serverAck from a recorded payload.
    They get added back by sign() and our send wrapper at runtime."""
    return {k: v for k, v in payload.items()
            if k not in ("time", "sig", "reqMsgID", "serverAck")}


def _resolve_tutorial_path(name: str) -> Path | None:
    """Look for Tutorial.txt next to this script, in CWD, or on the Desktop."""
    candidates = [
        Path(name),
        Path(__file__).with_name(name),
        Path(os.path.expanduser("~/OneDrive/Рабочий стол")) / name,
        Path(os.path.expanduser("~/Desktop")) / name,
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def load_tutorial(path: str = TUTORIAL_FILE) -> list[dict]:
    """
    Parse Tutorial.txt into a single ordered list of action templates.
    Every line whose first '{' decodes to a dict with an "action" key becomes
    a step, in file order. Most are signed-and-replayed verbatim; the special
    `_fish` directive (e.g. {"action":"_fish","count":6,"packs":"1-2"}) is an
    inline fishing instruction the player intercepts and runs at that point in
    the sequence (see _play_tutorial / _do_fishing) — it is never sent to the
    server. This lets Tutorial.txt fully own ordering, including interleaving
    fishing as many times as the real tutorial requires. The 'renamePenguin'
    step has the placeholder name swapped at runtime.
    """
    resolved = _resolve_tutorial_path(path)
    if resolved is None:
        return []  # don't crash at import; run_tutorial guards at use time
    # Walk line by line; find each line's first '{', JSON-decode the *whole
    # remainder* (handles nested objects like 'metric' payloads), keep
    # anything with an "action" key.
    steps: list[dict] = []
    dropped_actions: dict[str, int] = {}
    for raw in resolved.read_text(encoding="utf-8").splitlines():
        i = raw.find("{")
        if i < 0:
            continue
        candidate = raw[i:].rstrip()
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict) or "action" not in payload:
            continue
        action = payload["action"]
        if action in SKIP_ACTIONS:
            dropped_actions[action] = dropped_actions.get(action, 0) + 1
            continue
        steps.append(_strip_volatile(payload))
    if dropped_actions:
        print(f"[tutorial] skipped (SKIP_ACTIONS): {dropped_actions}", flush=True)
    return steps


# Parse once at import — cheap, immutable, shared across worker threads.
_TUTORIAL_STEPS: list[dict] = load_tutorial()


# ---------- NAMES ----------
_names_lock = threading.Lock()

def _generate_name() -> str:
    prefix = random.choice([
        "Frosty", "Snowy", "Chill", "Pengu", "Polar", "Glacier",
        "Icicle", "Slushy", "Arctic", "Blubber", "Iceberg", "Tundra",
    ])
    suffix = random.choice([
        "Joe", "Pal", "Buddy", "Bro", "Ace", "Boss", "Fin", "Pop",
        "Wave", "Drift", "Floe", "Star",
    ])
    n = random.randint(1, 99)
    return f"{prefix}{suffix}{n}"


def take_name(names_file: str = NAMES_FILE) -> str:
    """Pop the first non-comment line from names.txt. Rewrite the file
    without that line so reruns don't reuse it. Fall back to generator if
    names.txt is missing or exhausted."""
    p = Path(names_file)
    with _names_lock:
        if not p.exists():
            return _generate_name()
        lines = p.read_text(encoding="utf-8").splitlines()
        for i, raw in enumerate(lines):
            stripped = raw.strip()
            if stripped and not stripped.startswith("#"):
                lines.pop(i)
                p.write_text("\n".join(lines) + "\n", encoding="utf-8")
                return stripped
    return _generate_name()


def return_name(name: str, names_file: str = NAMES_FILE) -> None:
    """Put a name back into names.txt if the tutorial failed before the
    rename step succeeded. Best-effort; safe to call on success too (it
    won't double-return because we only call it from the failure path)."""
    with _names_lock:
        try:
            p = Path(names_file)
            content = p.read_text(encoding="utf-8") if p.exists() else ""
            p.write_text(content + name + "\n", encoding="utf-8")
        except Exception:
            pass


# ---------- ACCOUNTS.JSON I/O ----------
def _load_accounts() -> list[dict]:
    if not Path(ACCOUNTS_FILE).exists():
        return []
    try:
        return json.loads(Path(ACCOUNTS_FILE).read_text(encoding="utf-8")) or []
    except (json.JSONDecodeError, ValueError):
        return []


def _save_accounts(accounts: list[dict]) -> None:
    with _state_lock:
        Path(ACCOUNTS_FILE).write_text(json.dumps(accounts, indent=2), encoding="utf-8")


def _mark_completed(label: str, penguin_name: str) -> None:
    with _state_lock:
        accs = _load_accounts()
        for a in accs:
            if a.get("label") == label:
                a["tutorial_completed"]    = True
                a["tutorial_completed_at"] = int(time.time())
                a["penguin_name"]          = penguin_name
                break
        Path(ACCOUNTS_FILE).write_text(json.dumps(accs, indent=2), encoding="utf-8")


# ---------- WEBSOCKET HELPERS ----------
def _ws_connect(jwt: str, proxy_url: str | None) -> websocket.WebSocket:
    """Open a WS handshake. If proxy_url is provided, route through it
    (only HTTP/HTTPS proxies are supported by websocket-client).
    Starts a background keepalive ping every 20s so Cloudflare doesn't
    idle-close the socket mid-tutorial."""
    proxy_host = proxy_port = proxy_auth = proxy_type = None
    if proxy_url:
        # proxy_url is the requests-style http://user:pass@host:port
        m = re.match(r"^(https?)://(?:([^:]+):([^@]+)@)?([^:/]+):(\d+)$", proxy_url)
        if not m:
            raise RuntimeError(f"bad proxy url for websocket: {proxy_url!r}")
        proxy_type = m.group(1)
        user, pw   = m.group(2), m.group(3)
        proxy_host = m.group(4)
        proxy_port = int(m.group(5))
        proxy_auth = (user, pw) if user else None

    ws = websocket.create_connection(
        WS_URL,
        subprotocols=["pudgyprot", jwt],
        origin=ORIGIN,
        timeout=15,
        http_proxy_host=proxy_host,
        http_proxy_port=proxy_port,
        http_proxy_auth=proxy_auth,
        proxy_type=proxy_type,
        # Enable WS-level ping/pong. Cloudflare's idle threshold is ~60s;
        # 20s leaves comfortable headroom.
        enable_multithread=True,
    )

    # Start a daemon thread that sends WS-level ping frames. This is the
    # protocol-level ping, not a JSON action; Cloudflare and the Pudgy
    # server both reset the idle timer when they see it.
    stop_flag = threading.Event()
    def _pinger():
        while not stop_flag.is_set():
            if stop_flag.wait(20):
                return
            try:
                ws.ping()
            except Exception:
                return
    t = threading.Thread(target=_pinger, daemon=True)
    t.start()
    # Stash the stop flag on the ws so we can stop the pinger at close().
    ws._tutorial_pinger_stop = stop_flag  # type: ignore[attr-defined]
    return ws


def _ws_close(ws) -> None:
    """Stop the keepalive thread and close the WS."""
    if ws is None:
        return
    try:
        flag = getattr(ws, "_tutorial_pinger_stop", None)
        if flag is not None:
            flag.set()
    except Exception:
        pass
    try:
        ws.close()
    except Exception:
        pass


def _send_signed(ws, payload: dict) -> None:
    """Wrap payload with reqMsgID/serverAck/time/sig and ship."""
    # Use a fresh copy each send — sign() mutates the dict.
    body = dict(payload)
    body.setdefault("reqMsgID", 1)
    body.setdefault("serverAck", 0)
    ws.send(sign(body))


# Exceptions that mean "socket is dead — reconnect."
_DEAD_SOCKET_EXC = (
    websocket.WebSocketConnectionClosedException,
    ConnectionResetError,
    BrokenPipeError,
    OSError,           # generic "Bad file descriptor" / Windows WinError 10054
)


class _Session:
    """Wraps a single tutorial WebSocket with auto-reconnect.
    On any send/recv failure the socket is rebuilt and re-logged-in, then
    the caller's operation is retried. `label`, `jwt_fn`, `proxy_url`
    determine how a fresh socket is opened."""

    def __init__(self, label: str, proxy_url: str | None, log):
        self.label      = label
        self.proxy_url  = proxy_url
        self.log        = log
        self.ws: websocket.WebSocket | None = None
        # Per-account identity, captured from each loginResponse and used to
        # rewrite recorded `metric` payloads so they don't carry the original
        # recording account's player_id/session_id (which would tag every
        # tutorial with the same stale identity — an obvious correlation
        # signal). Refreshed on every reconnect because sessionID changes.
        self.player_id:  str | None = None
        self.session_id: str | None = None
        self._open_fresh()

    def _open_fresh(self):
        jwt = jwtharvest.ensure_fresh_token(self.label)
        self.ws = _ws_connect(jwt, self.proxy_url)
        self.ws.settimeout(RECV_TIMEOUT_SEC)
        _send_signed(self.ws, {"action": "login"})
        login = _wait_login_response(self.ws)
        # Both fields are at the top of the loginResponse frame; gameProfile.id
        # is the same UUID as playerID and is the documented fallback.
        self.player_id  = (login.get("playerID")
                           or login.get("gameProfile", {}).get("id"))
        self.session_id = login.get("sessionID")
        # Reset per-connection transient state. _pending_fish_id is only
        # valid for the active fishing session on the CURRENT socket; the
        # bite doesn't survive a reconnect, so any stale fishId from a prior
        # connection must not leak into a re-sent fishCaught.
        self._pending_fish_id = None  # type: ignore[attr-defined]
        # Cache the full login frame so callers can inspect tutorialComplete
        # / tutorialStepsCompleted without re-opening another WS.
        self._last_login = login  # type: ignore[attr-defined]

    def _reconnect(self) -> bool:
        """Close stale ws and open a fresh one (re-login included).
        Returns True on success; False after MAX_ATTEMPTS exhausted."""
        _ws_close(self.ws)
        self.ws = None
        for attempt in range(1, RECONNECT_MAX_ATTEMPTS + 1):
            delay = RECONNECT_BACKOFF_SEC[min(attempt - 1, len(RECONNECT_BACKOFF_SEC) - 1)]
            self.log(f"   !! socket dead — reconnect attempt {attempt}/{RECONNECT_MAX_ATTEMPTS} in {delay}s")
            time.sleep(delay)
            try:
                self._open_fresh()
                self.log(f"   ✓ reconnected")
                return True
            except Exception as e:
                self.log(f"   .. reconnect attempt {attempt} failed: {e!r}")
        return False

    # Last successful critical action — if the socket dies, we replay this
    # AND the failing payload on the new connection, because the server
    # may have rolled it back when the old connection dropped.
    _last_critical: dict | None = None

    def remember_critical(self, payload: dict) -> None:
        """Caller marks this payload as 'critical' once it's been ack'd
        (no server error within the drain window)."""
        self._last_critical = dict(payload)

    def send(self, payload: dict) -> None:
        """Best-effort single-payload send with one transparent reconnect +
        resend on a dead socket. Used for cosmetic slides and the fishing
        helpers (which run their own higher-level retry loops). For
        guaranteed scripted-step delivery use deliver()."""
        try:
            _send_signed(self.ws, payload)
            return
        except _DEAD_SOCKET_EXC as e:
            self.log(f"   send failed ({type(e).__name__}); reconnecting")
        if not self._reconnect():
            raise RuntimeError("tutorial: socket dead and reconnect exhausted")
        _send_signed(self.ws, payload)

    def deliver(self, payload: dict, confirm_seconds: float, log) -> str:
        """At-least-once delivery of ONE scripted action. Re-sends the SAME
        payload across reconnects so a socket death during send OR confirm
        never silently drops the step. The step is only considered done once
        it was sent on a socket that survived the confirm-drain. Returns:
            'ok'             sent on a live socket, confirm drained clean
            'benign'         server returned an 'already applied' error
            'rejected:<id>'  non-benign server error (retrying won't help)
            'failed'         exhausted MAX_STEP_ATTEMPTS without confirmation
        """
        action = payload.get("action")
        for attempt in range(1, MAX_STEP_ATTEMPTS + 1):
            # 1) ensure a live socket, then (re)send this exact payload.
            if self.ws is None and not self._reconnect():
                continue
            try:
                _send_signed(self.ws, dict(payload))
            except _DEAD_SOCKET_EXC:
                if attempt < MAX_STEP_ATTEMPTS:
                    log(f"      .. {action!r} send hit dead socket — reconnect & retry")
                self._reconnect()
                continue
            # 2) confirm: drain the confirm window. A dead socket here means
            #    we don't know whether the server committed, so reconnect and
            #    re-send (at-least-once; duplicates are benign for idempotent
            #    actions). A captured errorCode ends the attempt loop.
            captured = {"eid": None}
            def _cap(frame):
                e = frame.get("errorCode", {}).get("id")
                if e:
                    captured["eid"] = e
            try:
                _drain_strict(self.ws, confirm_seconds, on_error=_cap)
            except _DEAD_SOCKET_EXC:
                if attempt < MAX_STEP_ATTEMPTS:
                    log(f"      .. {action!r} confirm lost (socket died) — re-sending")
                self._reconnect()
                continue
            eid = captured["eid"]
            if eid is None:
                return "ok"
            if any(s in eid for s in BENIGN_ERROR_SUBSTRINGS):
                return "benign"
            return f"rejected:{eid}"
        return "failed"

    def drain(self, seconds: float, on_error=None) -> list[dict]:
        if self.ws is None: return []
        try:
            return _drain(self.ws, seconds, on_error=on_error)
        except _DEAD_SOCKET_EXC:
            self._reconnect()
            return []

    def close(self) -> None:
        _ws_close(self.ws)
        self.ws = None


def _drain(ws, seconds: float, on_error=None) -> list[dict]:
    """Consume server frames for `seconds`. Returns the list of parsed
    JSON frames. If a frame has an `errorCode`, the optional `on_error`
    callback is invoked with the parsed dict."""
    end = time.time() + seconds
    frames = []
    ws.settimeout(0.1)
    try:
        while time.time() < end:
            try:
                raw = ws.recv()
            except websocket.WebSocketTimeoutException:
                continue
            except Exception:
                break
            if not raw:
                continue
            try:
                j = json.loads(raw)
            except Exception:
                continue
            frames.append(j)
            if "errorCode" in j and on_error:
                on_error(j)
    finally:
        ws.settimeout(RECV_TIMEOUT_SEC)
    return frames


def _drain_strict(ws, seconds: float, on_error=None) -> list[dict]:
    """Like _drain, but RAISES on a dead socket instead of swallowing it, so
    deliver() can tell 'confirmed clean' apart from 'socket died mid-confirm'
    and re-send the step. Returns parsed frames on clean completion."""
    end = time.time() + seconds
    frames = []
    ws.settimeout(0.1)
    try:
        while time.time() < end:
            try:
                raw = ws.recv()
            except websocket.WebSocketTimeoutException:
                continue
            except _DEAD_SOCKET_EXC:
                raise
            except Exception:
                break
            if not raw:
                continue
            try:
                j = json.loads(raw)
            except Exception:
                continue
            frames.append(j)
            if "errorCode" in j and on_error:
                on_error(j)
    finally:
        try:
            ws.settimeout(RECV_TIMEOUT_SEC)
        except Exception:
            pass
    return frames


def _wait_login_response(ws) -> dict:
    ws.settimeout(15)
    while True:
        raw = ws.recv()
        if not raw:
            continue
        try:
            j = json.loads(raw)
        except Exception:
            continue
        if j.get("_action") == "loginResponse":
            return j
        if "errorCode" in j:
            raise RuntimeError(f"login server error: {j['errorCode'].get('id')}")


# ---------- TUTORIAL CORE ----------
def _slide_between_steps(sess: "_Session", log) -> None:
    """Tiny 0-2 slide burst between two consecutive tutorial steps. Kept
    deliberately small so a flood-induced disconnect (which the replay
    safety net then heals) only ever costs one critical-action replay."""
    n = random.randint(SLIDE_BETWEEN_MIN, SLIDE_BETWEEN_MAX)
    if n == 0:
        return
    log(f"   .. {n} slide action(s)")
    for _ in range(n):
        try:
            sess.send({
                "action":      "playerAction",
                "actionSlug":  "slide-distance",
                "amount":      random.randint(SLIDE_AMOUNT_MIN, SLIDE_AMOUNT_MAX),
            })
        except Exception:
            return
        time.sleep(random.uniform(SLIDE_PAUSE_MIN, SLIDE_PAUSE_MAX))
    sess.drain(0.2)


def _final_slide_flurry(sess: "_Session", log) -> None:
    """One-off slide burst at the very end of the tutorial — purely for
    natural-looking movement. Never runs between critical state actions."""
    n = random.randint(SLIDE_FINAL_COUNT_MIN, SLIDE_FINAL_COUNT_MAX)
    log(f"   .. final slide flurry: {n} slide action(s)")
    for _ in range(n):
        try:
            sess.send({
                "action":      "playerAction",
                "actionSlug":  "slide-distance",
                "amount":      random.randint(SLIDE_AMOUNT_MIN, SLIDE_AMOUNT_MAX),
            })
        except Exception:
            # Slides are cosmetic — if the server gets unhappy at the end,
            # we don't care, the tutorial is already complete.
            return
        time.sleep(random.uniform(SLIDE_PAUSE_MIN, SLIDE_PAUSE_MAX))
    sess.drain(0.2)


# Score jitter for submitScore steps. The recorded score in Tutorial.txt is
# the recording account's exact result; replayed verbatim it would mean every
# fleet account posts identical scores — a perfect correlation signal in
# Pudgy's analytics. ±SCORE_JITTER_RANGE breaks the obvious fingerprint while
# keeping the score plausibly close to a normal completion. SCORE_FLOOR keeps
# results positive even if jitter swings hard negative.
SCORE_JITTER_RANGE = 3000
SCORE_FLOOR        = 1


def _rewrite_identity(payload: dict, sess: "_Session") -> None:
    """Substitute the recording account's identity wherever it appears in a
    replayed payload. Tutorial.txt frames embed the recording UUID in three
    shapes; we handle all of them in one pass so each fleet account sends its
    own player_id / session_id rather than tagging every minigame profile and
    metric with one stale identity:

      1) Top-level `playerId` / `player_id`   (setMinigameProfile,
                                                getMinigameProfile, ...)
      2) Nested  payload.player_id            (metric)
      3) Nested  payload.session_id           (metric)

    Also refreshes the inner `ts` (separate from the top-level `time` that
    sign() sets) so traffic looks live, not replayed. Mutates in place;
    safe on payloads that don't have any of these fields."""
    # 1) Top-level player_id fields (camel + snake to be format-agnostic).
    if sess.player_id:
        if "playerId" in payload:
            payload["playerId"] = sess.player_id
        if "player_id" in payload:
            payload["player_id"] = sess.player_id

    # 2 & 3) Nested metric-style payload.
    inner = payload.get("payload")
    if isinstance(inner, dict):
        if sess.player_id and "player_id" in inner:
            inner["player_id"] = sess.player_id
        if sess.session_id and "session_id" in inner:
            inner["session_id"] = sess.session_id
        if "ts" in inner:
            now = datetime.now(timezone.utc)
            inner["ts"] = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _jitter_score(payload: dict, log) -> None:
    """submitScore-only: nudge the recorded `score` by ±SCORE_JITTER_RANGE so
    a fleet doesn't post 200 identical results. No-op if `score` is missing."""
    if "score" not in payload:
        return
    try:
        original = int(payload["score"])
    except (TypeError, ValueError):
        return
    jittered = max(SCORE_FLOOR, original + random.randint(-SCORE_JITTER_RANGE, SCORE_JITTER_RANGE))
    payload["score"] = jittered
    log(f"   .. score jittered {original} -> {jittered}")


def _tg_status_text(label: str, name: str, step_idx: int, total: int,
                    action: str, status: str, errors: int) -> str:
    """Compose the single-message status text. Same shape every step so
    Telegram shows a clean in-place update."""
    pct = int(100 * (step_idx + 1) / total) if total else 0
    bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
    err_line = f"\n⚠️ errors: {errors}" if errors else ""
    return (
        f"🎮 Tutorial — {label}\n"
        f"penguin: {name}\n"
        f"[{bar}] {pct}%  step {step_idx + 1}/{total}\n"
        f"{status}: {action}{err_line}"
    )


def _robust_start_fishing(sess: "_Session", payload: dict, log) -> int | None:
    """Send startFishing and consume fishingStarted + fishBite, retrying the
    WHOLE handshake across reconnects. Returns the bite's fishId (or None if
    it never completed). A follow-up fishEscaped / fishCaught is rejected
    unless an active fishing session with a pending bite exists, so we must
    re-establish the whole thing after any mid-handshake socket death."""
    for attempt in range(1, MAX_STEP_ATTEMPTS + 1):
        try:
            if sess.ws is None and not sess._reconnect():
                continue
            _send_signed(sess.ws, dict(payload))
            started = _recv_until(sess.ws, "fishingStarted", timeout=FISH_ACK_TIMEOUT)
            t    = float(started.get("t", 10.0))
            bite = _recv_until(sess.ws, "fishBite", timeout=t + FISH_BITE_BUFFER_SEC)
            fid  = bite.get("fishBite", {}).get("fishId")
            log(f"      .. fishBite (fishId={fid}, server_t={t:.1f}s)")
            return fid
        except ServerRejected as e:
            # Logical reject (e.g. already fishing) — retrying won't help.
            log(f"      << startFishing rejected: {e.error_id}")
            return None
        except _DEAD_SOCKET_EXC:
            if attempt < MAX_STEP_ATTEMPTS:
                log("      .. startFishing handshake lost (socket died) — retry")
            sess._reconnect()
            continue
        except Exception as e:
            # Includes recv timeout waiting for the bite. Reconnect & retry.
            if attempt < MAX_STEP_ATTEMPTS:
                log(f"      .. startFishing handshake error ({e!r}) — retry")
            sess._reconnect()
            continue
    log("   !! startFishing gave up after retries")
    return None


def _robust_fish_fight(sess: "_Session", start_payload: dict,
                       finish_payload: dict, log, fight_index: int = 0) -> str:
    """One ATOMIC boss-fish attempt: startFishing -> fishingStarted ->
    fishBite -> finish (fishEscaped / fishCaught), all on the SAME live
    socket. fishEscaped's breakpointsBroken echoes the exact breakPoints the
    server sent in this fishBite.

    Deliberately simple: we send the attempt once and move on. There is NO
    re-fish-to-verify-counting and NO mid-fight login refresh — those caused
    the awful, item-wasting behavior. The only retry is when the socket
    physically dies before/while we get the bite (the finish can't be sent
    without an active bite), in which case we re-establish the bite on a
    fresh socket. Returns 'ok' | 'rejected:<id>' | 'failed'."""
    faction = finish_payload.get("action")
    for attempt in range(1, MAX_STEP_ATTEMPTS + 1):
        try:
            if sess.ws is None and not sess._reconnect():
                continue
            # 1) engage
            _send_signed(sess.ws, dict(start_payload))
            started = _recv_until(sess.ws, "fishingStarted", timeout=FISH_ACK_TIMEOUT)
            t    = float(started.get("t", 10.0))
            bite = _recv_until(sess.ws, "fishBite", timeout=t + FISH_BITE_BUFFER_SEC)
            fb   = bite.get("fishBite", {}) or {}
            fid  = fb.get("fishId")
            # 2) build the finish payload and send it on the SAME socket
            fp = dict(finish_payload)
            if faction == "fishCaught" and fid is not None:
                fp["fishId"] = fid
            if faction == "fishEscaped":
                live_bp = list(fb.get("breakPoints") or [])
                fp["breakpointsBroken"] = live_bp   # echo exact breakPoints
                log(f"      .. breakpointsBroken = {live_bp}  "
                    f"(echoed {len(live_bp)} live breakpoints)")
            time.sleep(random.uniform(1.5, 3.0))  # brief fight pacing
            _send_signed(sess.ws, fp)
            # 3) drain the ack; surface a reject, and log quest progress for
            #    visibility (no action taken on it — single attempt).
            captured = {"eid": None, "frames": []}
            def _cap(frame):
                captured["frames"].append(frame)
                e = frame.get("errorCode", {}).get("id")
                if e:
                    captured["eid"] = e
            _drain_strict(sess.ws, 2.0, on_error=_cap)
            eid = captured["eid"]
            if eid and not any(s in eid for s in BENIGN_ERROR_SUBSTRINGS):
                log(f"      << {faction} rejected: {eid}")
                return f"rejected:{eid}"
            counted = False
            for fr in captured["frames"]:
                act = fr.get("_action", "?")
                sqp = fr.get("storyQuestProgress") or {}
                for qid, q in sqp.items():
                    removed = q.get("itemsRemoved") or []
                    if removed:
                        counted = True
                    log(f"      << {act} quest {qid}: "
                        f"completed={q.get('completedTasks')} "
                        f"eligible={q.get('eligibleTasks')} "
                        f"complete={q.get('complete')} itemsRemoved={removed}")
            log(f"      .. fight ok (fishId={fid}, {faction}, counted={counted})")
            return "ok"
        except ServerRejected as e:
            log(f"      << fight rejected: {e.error_id}")
            return f"rejected:{e.error_id}"
        except _DEAD_SOCKET_EXC:
            if attempt < MAX_STEP_ATTEMPTS:
                log("      .. fight lost (socket died) — re-establishing bite")
            sess._reconnect()
            continue
        except Exception as e:
            if attempt < MAX_STEP_ATTEMPTS:
                log(f"      .. fight error ({e!r}) — re-establishing bite")
            sess._reconnect()
            continue
    return "failed"


def _verify_and_repair(sess: "_Session", log,
                       errors_by_step: dict[int, str]) -> None:
    """End-of-run sanity check. Re-login on the existing session to refresh
    the loginResponse, then:
      1) collect every `completeTutorialStep` tutorialId from Tutorial.txt
      2) read the server's tutorialStepsCompleted set
      3) for any expected ID NOT on the server, re-send completeTutorialStep
         (deliver() treats AlreadyExists as benign, so duplicates are safe)
      4) log final tutorialComplete state + any leftover gaps
    Best-effort: any error here is non-fatal, the tutorial already ran."""
    # Expected tutorialIds from the script.
    expected_ids: set[int] = set()
    for st in _TUTORIAL_STEPS:
        if st.get("action") == "completeTutorialStep" and "tutorialId" in st:
            try:
                expected_ids.add(int(st["tutorialId"]))
            except (TypeError, ValueError):
                pass
    if not expected_ids:
        return

    # Force a fresh login frame.
    try:
        _send_signed(sess.ws, {"action": "login"})
        login = _wait_login_response(sess.ws)
    except _DEAD_SOCKET_EXC:
        if not sess._reconnect():
            log("   !! verify: socket dead & reconnect exhausted")
            return
        login = sess._last_login  # set by _open_fresh
    except Exception as e:
        log(f"   !! verify login refresh failed: {e!r}")
        return

    server_done = set(int(x) for x in (login.get("tutorialStepsCompleted") or [])
                      if isinstance(x, (int, float, str)) and str(x).lstrip("-").isdigit())
    tutorial_complete = bool(login.get("tutorialComplete", False))
    missing = sorted(expected_ids - server_done)

    log(f"   .. verify: tutorialComplete={tutorial_complete}  "
        f"expected={len(expected_ids)}  done={len(expected_ids & server_done)}  "
        f"missing={missing if missing else 'none'}")

    if not missing:
        return

    # Re-send each missing completeTutorialStep. deliver() handles
    # AlreadyExists as benign, so we won't double-credit anything.
    log(f"   .. repairing {len(missing)} missing tutorialStep(s)")
    for tid in missing:
        payload = {
            "action":     "completeTutorialStep",
            "tutorialId": tid,
            "reqMsgID":   1,
            "serverAck":  0,
        }
        status = sess.deliver(payload, 1.2, log)
        if status in ("ok", "benign"):
            log(f"      ✓ repaired tutorialId={tid}")
        else:
            log(f"      .. tutorialId={tid} repair status={status}")
            # Stash under a synthetic step index so the summary surfaces it.
            errors_by_step[-tid] = f"repair_failed:{status}"


def _play_tutorial(sess: "_Session", penguin_name: str, log,
                   label: str = "", tg_mid: int | None = None) -> dict:
    """Walk the parsed Tutorial.txt step list in order. Returns a summary dict
    {ok, errors_by_step}. Errors are logged per step but the run continues
    (most tutorial errors are non-fatal: missing prerequisite, duplicate
    pickup, etc.) so later steps still execute.

    A step whose action is `_fish` is NOT sent to the server — it's an inline
    fishing directive, so we run a full buy-bait + catch loop at that position
    and move on. This lets Tutorial.txt interleave fishing anywhere, any number
    of times, without code changes."""
    errors_by_step: dict[int, str] = {}
    last_step_for_error: list[int] = [0]  # mutable holder for the callback
    # Steps already executed as part of an atomic boss-fish fight (the
    # fishEscaped/fishCaught consumed by the preceding startFishing). Skipped
    # when the loop reaches them.
    consumed_steps: set[int] = set()

    def on_error(frame):
        s = last_step_for_error[0]
        eid = frame.get("errorCode", {}).get("id", "?")
        errors_by_step[s] = eid
        log(f"      << SERVER ERROR step {s}: {eid}")

    # Actions that change persistent game state and MUST be fully persisted
    # before the next send (otherwise a mid-burst disconnect can corrupt
    # the chain). After these we drain longer. Boogie-berg additions:
    # setMinigameProfile, submitScore, markTraitsSeen, updatePenguinTraits,
    # uploadProfilePic are all server-side commits the next step often
    # depends on, so they belong here too.
    CRITICAL_ACTIONS = {
        "pickupSecret", "talkToNpc", "crackEgg", "completeTutorialStep",
        "completeTutorial", "renamePenguin", "purchaseStoreItem",
        "setCurrentBait", "startFishing", "updateLastScene",
        "setMinigameProfile", "submitScore", "markTraitsSeen",
        "updatePenguinTraits", "uploadProfilePic",
        # Boogie-berg fishEscaped sequence + obby/badge claims commit
        # quest progress server-side; the next step usually depends on it.
        "fishEscaped", "fishCaught", "claimBadgeRewards", "endObby",
        # spotlightSeen between Bonko attempts dismisses a UI gate the
        # server tracks per-player; treat it as critical so the drain
        # surfaces any reject before the next startFishing.
        "spotlightSeen",
    }

    # Slide gate: stays False until we successfully send `completeTutorial`.
    # Before that, the action chain is too fragile (one bad slide-induced
    # disconnect rolls back state and the rest of the tutorial silently
    # corrupts). After `completeTutorial`, the server has committed the
    # main tutorial flag and subsequent actions are post-tutorial polish.
    slides_unlocked = False

    total = len(_TUTORIAL_STEPS)
    fight_counter = 0  # counts boss-fish attempts, drives escape escalation
    for i, template in enumerate(_TUTORIAL_STEPS):
      if i in consumed_steps:
          continue  # already executed as the finish of an atomic fight
      # Outer guard: ANY unexpected exception in a single step is caught,
      # logged as a delivery failure, and the next step still runs. Without
      # this, one bad payload or a transient KeyError would abort the entire
      # tutorial — guaranteed-delivery is moot if the iteration itself dies.
      try:
        last_step_for_error[0] = i
        payload = dict(template)
        action = payload.get("action")

        # Inline fishing directive — run a buy-bait + catch loop here instead
        # of sending anything. Non-fatal: a fishing hiccup doesn't abort the
        # scripted tutorial.
        if action == "_fish":
            count = int(payload.get("count", 0))
            packs = payload.get("packs")
            log(f"   step {i}: FISH count={count} packs={packs}")
            if tg_mid is not None:
                tg.edit(tg_mid, _tg_status_text(
                    label, penguin_name, i, total,
                    f"fishing x{count}", "running", len(errors_by_step)))
            try:
                _do_fishing(sess, log, count, packs)
            except Exception as e:
                log(f"   !! fishing directive failed: {e!r}")
            time.sleep(random.uniform(STEP_PAUSE_MIN, STEP_PAUSE_MAX))
            continue

        if action == "renamePenguin":
            payload["penguinName"] = penguin_name
        # Unconditionally substitute this account's identity wherever the
        # recording UUID appears (top-level playerId for setMinigameProfile/
        # getMinigameProfile, nested payload.player_id/session_id for metric).
        # No-op on payloads that don't contain those fields.
        _rewrite_identity(payload, sess)
        # submitScore: nudge the recorded score so the fleet doesn't post
        # 200 identical results. No-op on any other action.
        if action == "submitScore":
            _jitter_score(payload, log)
        log(f"   step {i}: {action}"
            + (f" tutorialId={payload['tutorialId']}" if "tutorialId" in payload else "")
            + (f" npc={payload['npcInstanceSlug']}"   if "npcInstanceSlug" in payload else ""))
        if tg_mid is not None:
            tg.edit(tg_mid, _tg_status_text(
                label, penguin_name, i, total,
                action, "running", len(errors_by_step)))

        # startFishing is interactive. Two cases:
        #  (a) immediately followed by fishEscaped/fishCaught (a Bonko-style
        #      boss fight): run the WHOLE attempt atomically so the finish
        #      lands on the same live socket as the bite. Consume the finish
        #      step so the loop doesn't re-send it standalone.
        #  (b) lone startFishing (early "learn to fish" step): just establish
        #      a bite via the retrying handshake.
        if action == "startFishing":
            nxt = _TUTORIAL_STEPS[i + 1] if i + 1 < total else None
            nxt_action = nxt.get("action") if nxt else None
            log(f"   step {i}: startFishing"
                + (f" -> {nxt_action}" if nxt_action in ("fishEscaped", "fishCaught") else ""))
            if tg_mid is not None:
                tg.edit(tg_mid, _tg_status_text(
                    label, penguin_name, i, total,
                    f"fishing ({nxt_action or 'start'})", "running", len(errors_by_step)))
            if nxt_action in ("fishEscaped", "fishCaught"):
                finish = dict(nxt)
                _rewrite_identity(finish, sess)
                status = _robust_fish_fight(sess, payload, finish, log,
                                            fight_index=fight_counter)
                fight_counter += 1
                if status.startswith("rejected:"):
                    errors_by_step[i] = status.split(":", 1)[1]
                elif status == "failed":
                    errors_by_step[i] = "fight_failed"
                    log(f"      << FIGHT FAILED step {i} after {MAX_STEP_ATTEMPTS} attempts")
                consumed_steps.add(i + 1)  # finish handled inside the fight
            else:
                fid = _robust_start_fishing(sess, payload, log)
                sess._pending_fish_id = fid  # type: ignore[attr-defined]
            time.sleep(random.uniform(STEP_PAUSE_MIN, STEP_PAUSE_MAX))
            continue

        # fishCaught (only if Tutorial.txt ever uses it raw, not via _fish):
        # fill in the live fishId from the most recent bite so we don't send
        # the recording's stale id.
        if action == "fishCaught":
            fid = getattr(sess, "_pending_fish_id", None)
            if fid is not None:
                payload["fishId"] = fid

        # Guaranteed delivery: re-sends this exact step across reconnects
        # until it lands on a socket that survives the confirm window.
        is_critical  = action in CRITICAL_ACTIONS
        drain_window = 1.2 if is_critical else 0.4
        status = sess.deliver(payload, drain_window, log)
        if status in ("ok", "benign"):
            pass  # step landed (benign = "server says it was already done")
        elif status.startswith("rejected:"):
            eid = status.split(":", 1)[1]
            errors_by_step[i] = eid
            log(f"      << SERVER ERROR step {i}: {eid}")
        else:  # "failed"
            errors_by_step[i] = "delivery_failed"
            log(f"      << DELIVERY FAILED step {i} ({action}) "
                f"after {MAX_STEP_ATTEMPTS} attempts")

        # Unlock slides only after completeTutorial has been delivered without
        # a non-benign error.
        if action == "completeTutorial" and i not in errors_by_step:
            slides_unlocked = True
            log(f"   .. slides unlocked")

        time.sleep(random.uniform(STEP_PAUSE_MIN, STEP_PAUSE_MAX))

        # Insert a tiny slide burst BETWEEN steps, but only:
        #   (a) AFTER completeTutorial has been sent (slides_unlocked)
        #   (b) NOT right before a high-risk action (pickupSecret, crackEgg,
        #       or a fishing directive — fishing manages its own socket).
        # Both gates must pass for a slide burst to fire.
        if slides_unlocked and i + 1 < total:
            next_action = _TUTORIAL_STEPS[i + 1].get("action")
            if next_action not in SLIDE_BLOCKED_BEFORE and next_action != "_fish":
                _slide_between_steps(sess, log)
      except Exception as step_exc:
        # Any unexpected exception in a single step: log, mark as failed,
        # continue with the next step. The run no longer dies on one bad
        # step — guaranteed delivery is meaningless if the iteration aborts.
        errors_by_step[i] = f"step_exception:{type(step_exc).__name__}"
        log(f"      !! step {i} crashed: {step_exc!r} — continuing")

    # Critical: let the server finish persisting before we do anything else.
    log(f"   .. final settle window ({FINAL_DRAIN_SEC}s)")
    sess.drain(FINAL_DRAIN_SEC, on_error=on_error)

    # Post-tutorial verification: re-open the WS so the server hands us a
    # fresh loginResponse, then read tutorialComplete and the set of
    # tutorialStepsCompleted. This catches the case where the scripted run
    # appeared clean but the server is missing a tutorialStep we sent. If
    # any expected step ID is missing, retry it (the deliver() path handles
    # AlreadyExists as benign, so re-sending a step already on the server
    # is harmless).
    try:
        _verify_and_repair(sess, log, errors_by_step)
    except Exception as e:
        log(f"   !! verification skipped: {e!r}")

    # All state-changing actions done and acknowledged — NOW play the slide
    # flurry for natural-looking movement. Even if the socket dies during
    # this, the tutorial is already complete on the server.
    _final_slide_flurry(sess, log)

    return {
        "ok":               total - len(errors_by_step),
        "errors_by_step":   errors_by_step,
    }


# ---------- POST-TUTORIAL FISHING ----------
class ServerRejected(RuntimeError):
    """Server returned an errorCode frame during an interactive handshake.
    Distinct from transport (_DEAD_SOCKET_EXC) failures so callers can tell a
    logical reject (don't retry) from a socket death (reconnect & retry)."""
    def __init__(self, error_id: str):
        super().__init__(f"server error: {error_id}")
        self.error_id = error_id


def _recv_until(ws, name: str, timeout: float = 15.0) -> dict:
    """Read frames until one with `_action == name` arrives. Raises
    ServerRejected on an errorCode frame, or a _DEAD_SOCKET_EXC if the socket
    dies. Used for the interactive fishing handshake where drain()'s
    fire-and-forget model isn't enough."""
    ws.settimeout(timeout)
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


def _buy_bait(sess: "_Session", log, packs: int = 1) -> None:
    """Buy `packs` bait packs (each pack = BAIT_PER_PACK bait)."""
    payload = {
        "action":      "purchaseStoreItem",
        "storeItemId": BAIT_STORE_ITEM_ID,
        "currencyId":  BAIT_CURRENCY_ID,
    }
    for _ in range(packs):
        sess.send(dict(payload))
        sess.drain(1.0)
        time.sleep(random.uniform(STEP_PAUSE_MIN, STEP_PAUSE_MAX))
    sess.remember_critical(dict(payload))
    log(f"   bought {packs} bait pack(s) (+{packs * BAIT_PER_PACK} bait)")


# ---- fishing reliability tuning ----
# Extra time on top of the server-reported `t` to wait for the fishBite
# frame. Without this we hit a flat 15s ceiling and rare/long-timer fish
# silently fail.
FISH_BITE_BUFFER_SEC   = 10.0
# How long to wait for the fishingStarted ack and the post-catch fishRewarded
# ack — these are server-side instant, generous timeout is just safety.
FISH_ACK_TIMEOUT       = 15.0
FISH_REWARD_TIMEOUT    = 10.0
# After a failed catch the server's fishing slot is still "open" for a few
# seconds. Drain late frames then sleep so the next startFishing isn't
# rejected with AlreadyFishing / InvalidState.
FISH_RECOVER_DRAIN_SEC = 2.5
FISH_RECOVER_SLEEP_SEC = 3.0
# Per-fish retry budget (extra attempts after the initial try).
FISH_MAX_RETRIES       = 2


def _catch_one(sess: "_Session", log) -> bool:
    """One full fishing cycle. The recv timeout for `fishBite` is derived
    from the server's `t` (timer until bite) reported in `fishingStarted` —
    not a flat 15s — so rare fish with long timers don't time out and burn
    a bait. Raises on any server error or timeout; the caller decides
    whether to retry."""
    sess.send({"action": "startFishing", "holeId": HOLE_ID, "baitId": BAIT_ID})
    started = _recv_until(sess.ws, "fishingStarted", timeout=FISH_ACK_TIMEOUT)
    t       = float(started.get("t", 10.0))
    bite    = _recv_until(sess.ws, "fishBite", timeout=t + FISH_BITE_BUFFER_SEC)
    fish_id = bite["fishBite"]["fishId"]
    sess.send({"action": "fishCaught", "fishId": fish_id, "holeId": HOLE_ID})
    _recv_until(sess.ws, "fishRewarded", timeout=FISH_REWARD_TIMEOUT)
    log(f"   caught fish {fish_id}")
    return True


def _try_catch_one(sess: "_Session", log) -> bool:
    """Wrap `_catch_one` with bounded retries + server-state recovery. After
    a failure we drain stray frames and sleep before retrying so the server's
    open fishing slot expires — otherwise the next startFishing cascades
    (AlreadyFishing -> next fails -> next fails ... until bait is gone)."""
    last_err = None
    for attempt in range(1 + FISH_MAX_RETRIES):
        try:
            return _catch_one(sess, log)
        except Exception as e:
            last_err = e
            log(f"   .. catch attempt {attempt + 1} failed: {e!r}")
            if attempt < FISH_MAX_RETRIES:
                try:
                    sess.drain(FISH_RECOVER_DRAIN_SEC)
                except Exception:
                    pass
                time.sleep(FISH_RECOVER_SLEEP_SEC)
    log(f"   !! gave up after {1 + FISH_MAX_RETRIES} attempts: {last_err!r}")
    return False


def _resolve_packs(count: int, packs_spec) -> int:
    """Resolve a `_fish` directive's `packs` field to a concrete pack count.
    None -> ceil(count/BAIT_PER_PACK); int -> as-is; "a-b" -> random in [a,b]."""
    if packs_spec is None:
        return -(-count // BAIT_PER_PACK)  # ceil: always enough bait
    if isinstance(packs_spec, str) and "-" in packs_spec:
        lo, hi = packs_spec.split("-", 1)
        return random.randint(int(lo), int(hi))
    return int(packs_spec)


def _do_fishing(sess: "_Session", log, count: int, packs_spec=None) -> int:
    """One fishing directive: buy bait, then land `count` fish. Each catch
    goes through `_try_catch_one` (bounded retries + server-state recovery)
    so a single rare-fish timeout doesn't strand the run at 6 or 7 of 10."""
    packs = _resolve_packs(count, packs_spec)
    _buy_bait(sess, log, packs=packs)
    caught = 0
    for _ in range(count):
        if _try_catch_one(sess, log):
            caught += 1
        time.sleep(random.uniform(STEP_PAUSE_MIN, STEP_PAUSE_MAX))
    log(f"   fishing: caught {caught}/{count} (packs bought: {packs})")
    return caught


def run_tutorial(account: dict, proxy_url: str | None = None,
                 force: bool = False) -> dict:
    """
    Public entry point. Mutates the account dict in place on success:
      account['tutorial_completed'] = True
      account['penguin_name']       = <chosen name>
    On failure, raises. The account dict is NOT marked completed.
    Writes the change to accounts.json (atomic under lock) on success.

    `force=True` re-runs even if the account is already marked complete. This
    is safe to do: the per-step delivery treats 'already applied' server
    errors as success, so a replay re-attempts only the steps that never
    landed and no-ops the rest. Used to repair an account that finished with
    dropped steps (e.g. a quest left stuck by a flaky proxy).
    """
    label = account["label"]
    def log(msg): print(f"[tutorial:{label}] {msg}", flush=True)

    if account.get("tutorial_completed") and not force:
        log("already completed; skipping")
        return account
    if account.get("tutorial_completed") and force:
        log("already completed — FORCE re-run (idempotent replay)")
    if not _TUTORIAL_STEPS:
        raise RuntimeError(
            f"{TUTORIAL_FILE} not found or empty. Place it next to tutorial.py "
            f"(or in the project root) and try again."
        )

    # Ensure JWT is fresh — full Ory re-login if expired/missing.
    jwt = jwtharvest.ensure_fresh_token(label)
    account["access_token"]      = jwt
    account["access_expires_at"] = jwtharvest._decode_jwt_exp(jwt)

    name = account.get("penguin_name") or take_name()
    log(f"opening WS (proxy={'yes' if proxy_url else 'no'}) name={name}")

    # One Telegram message per account that we edit in place per step.
    tg_mid = tg.send(
        f"🎮 Tutorial starting — {label}\n"
        f"penguin: {name}\n"
        f"[░░░░░░░░░░] 0%  step 0/{len(_TUTORIAL_STEPS)}"
    )

    name_was_taken = name != account.get("penguin_name")
    sess = None
    try:
        # Retry initial session creation. A flaky proxy at the exact moment
        # of first handshake shouldn't kill an otherwise-fine tutorial run.
        # Each attempt does: ensure JWT -> open WS through proxy -> login ->
        # wait for loginResponse. Mirrors what _reconnect does later.
        last_err = None
        for boot_attempt in range(1, SESSION_BOOT_MAX_ATTEMPTS + 1):
            try:
                sess = _Session(label, proxy_url, log)
                break
            except Exception as e:
                last_err = e
                log(f"   !! session boot attempt {boot_attempt}/"
                    f"{SESSION_BOOT_MAX_ATTEMPTS} failed: {e!r}")
                if boot_attempt < SESSION_BOOT_MAX_ATTEMPTS:
                    delay = SESSION_BOOT_BACKOFF_SEC[
                        min(boot_attempt - 1, len(SESSION_BOOT_BACKOFF_SEC) - 1)]
                    log(f"      .. retrying in {delay}s")
                    time.sleep(delay)
        if sess is None:
            raise RuntimeError(
                f"session boot exhausted after {SESSION_BOOT_MAX_ATTEMPTS} "
                f"attempts: {last_err!r}")
        log("logged in; starting tutorial script")
        summary = _play_tutorial(sess, name, log, label=label, tg_mid=tg_mid)
        errs = summary["errors_by_step"]
        if errs:
            log(f"tutorial finished with {len(errs)} server error(s): {errs}")
            tg.edit(tg_mid,
                    f"⚠️ Tutorial done — {label}\n"
                    f"penguin: {name}\n"
                    f"[██████████] 100%  finished with {len(errs)} server error(s)\n"
                    f"errors: {errs}")
        else:
            log("tutorial done OK (no server errors)")
            tg.edit(tg_mid,
                    f"✅ Tutorial done — {label}\n"
                    f"penguin: {name}\n"
                    f"[██████████] 100%  all {len(_TUTORIAL_STEPS)} steps OK")
        tg.flush(tg_mid)
    except Exception as e:
        if name_was_taken:
            return_name(name)
        tg.edit(tg_mid,
                f"❌ Tutorial FAILED — {label}\n"
                f"penguin: {name}\n"
                f"error: {type(e).__name__}: {e}")
        tg.flush(tg_mid)
        raise
    finally:
        if sess is not None:
            sess.close()

    # Success path: persist to accounts.json atomically.
    _mark_completed(label, name)
    account["tutorial_completed"]    = True
    account["tutorial_completed_at"] = int(time.time())
    account["penguin_name"]          = name
    return account


# ---------- CLI ----------
def _cli():
    """Backfill mode: scan accounts.json and run the tutorial for every
    account where tutorial_completed != true. Optional positional args
    filter to specific labels.

    Flags:
      --force / -f   re-run even accounts already marked tutorial_completed.
                     Safe (idempotent replay) — use to repair an account
                     left with dropped steps. Best paired with explicit
                     label(s), e.g.  python tutorial.py --force auto_0003
    """
    args = sys.argv[1:]
    force = False
    labels = []
    for a in args:
        if a in ("--force", "-f"):
            force = True
        else:
            labels.append(a)

    accs = _load_accounts()
    if not accs:
        print(f"!! {ACCOUNTS_FILE} is empty"); sys.exit(1)

    if labels:
        wanted = set(labels)
        accs = [a for a in accs if a.get("label") in wanted]

    # With --force, completed accounts are eligible too; otherwise only
    # those not yet completed.
    if force:
        pending = list(accs)
    else:
        pending = [a for a in accs if not a.get("tutorial_completed")]
    print(f">> {len(pending)} account(s) to run"
          + (" (FORCE)" if force else "")
          + f"; running with {min(len(pending), TUTORIAL_CONCURRENCY)} in parallel")

    if not pending:
        print("== nothing to do"); sys.exit(0)

    ok = fail = 0
    with ThreadPoolExecutor(max_workers=TUTORIAL_CONCURRENCY) as pool:
        futures = {pool.submit(run_tutorial, a, a.get("proxy_raw"), force): a for a in pending}
        for fut in as_completed(futures):
            a = futures[fut]
            try:
                fut.result()
                ok += 1
            except Exception as e:
                fail += 1
                print(f"[tutorial:{a.get('label')}] FAILED: {e}", flush=True)
    print(f"== tutorial backfill done: {ok} ok, {fail} failed")
    sys.exit(0 if fail == 0 else 1)


if __name__ == "__main__":
    _cli()
