"""
PudgyWorld auto-fisher — proof-of-concept exploit.
Runs entirely from Python. No browser, no UI, no mouse.

Setup:
  pip uninstall -y websocket websocket-client
  pip install websocket-client
  (Open the game in Chrome ONCE to grab a fresh `jwt_prod` cookie, then close ALL
   tabs of pudgyworld.com before running this script — server kicks duplicate sessions.)
"""

import websocket, json, hmac, hashlib, base64, time, sys, threading, ssl
import urllib.request, urllib.parse
from datetime import datetime, timezone

# Local module — handles full Ory login + accounts.json writeback.
import jwtharvest

# Telegram-only TLS context: skip cert verification so we still work behind
# corporate proxies / self-signed CA chains. Safe here — we're only sending
# notification text, never receiving sensitive data.
_TG_SSL = ssl.create_default_context()
_TG_SSL.check_hostname = False
_TG_SSL.verify_mode = ssl.CERT_NONE

# ===================== TELEGRAM =====================
TG_BOT_TOKEN     = "8991199892:AAFUWF35cOw-FMWLTOdNVkR2x44cNTu5ZMg"
TG_CHAT_ID       = "769594408"
TG_STATS_EVERY   = 25   # also send an overall stats message every N catches

def tg_send(text: str):
    """Fire-and-forget: runs the HTTP call in a background thread so the
    main WebSocket loop is never blocked (avoids missed ping → dead socket)."""
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    def _go():
        try:
            urllib.request.urlopen(
                urllib.request.Request(
                    f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
                    data=urllib.parse.urlencode({
                        "chat_id": TG_CHAT_ID,
                        "text": text,
                    }).encode(),
                ),
                timeout=10,
                context=_TG_SSL,
            ).read()
        except Exception as e:
            print(f"[tg] send failed: {e!r}", flush=True)
    threading.Thread(target=_go, daemon=True).start()

# ===================== CONFIG =====================
KEY = b"wB7FLqHISDjBxCaklTFafvUpacahD5ocMORUkR+PpJI="

# Which account in accounts.json to run as. Must also exist in credentials.txt
# (format: `label:email:password` per line).
ACCOUNT_LABEL = "main"

# Refresh the JWT if it expires within this many seconds. The token's lifetime
# is ~24h, so 5 min of slack is plenty and saves us from mid-cast expiry.
JWT_REFRESH_SKEW = 300

def fetch_jwt() -> str:
    """Get a valid access token for ACCOUNT_LABEL, re-running the Ory login
    flow (and rewriting accounts.json) if the current token is expired or
    about to be. Returns the access_token string."""
    log("AUTH", f"ensuring fresh JWT for label={ACCOUNT_LABEL!r}")
    tok = jwtharvest.ensure_fresh_token(ACCOUNT_LABEL, skew_seconds=JWT_REFRESH_SKEW)
    log("AUTH", f"JWT ready (len={len(tok)}, first 40: {tok[:40]}...)")
    return tok

JWT = ""  # populated by fetch_jwt() before each connect()

WS_URL   = "wss://pudgyworld.pudgyworld.com/ws?ver=0.8.4&g=1"
ORIGIN   = "https://play.pudgyworld.com"
HOLE_ID  = 11
BAIT_ID  = 1
BAIT_STORE_ITEM_ID = 18      
RECV_TIMEOUT = 20            # seconds to wait for a specific server reply
PRINT_RAW_FRAMES = True      # set False for quieter output

# ===================== LOGGING =====================
def log(tag, msg=""):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"[{ts}] {tag:8s} {msg}", flush=True)

# ===================== SIGNING =====================
def sign(payload: dict) -> str:
    # Millisecond precision — must vary between retries or server's replay
    # detection (ClientValidateSigReplayDetected) will reject the duplicate sig.
    now = datetime.now(timezone.utc)
    payload["time"] = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    canon = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload["sig"] = base64.b64encode(
        hmac.new(KEY, canon.encode(), hashlib.sha256).digest()
    ).decode()
    return json.dumps(payload, sort_keys=True)

# ===================== CONNECT (reconnectable) =====================
ws = None  # type: ignore  — set by connect()

class Reconnect(Exception):
    """Raised whenever the socket needs to be torn down and reopened."""

def connect(initial: bool = False):
    """(Re)open the WebSocket. Raises on failure. Always refreshes the JWT
    first if it's missing or close to expiry — so reconnects after a long
    outage automatically pick up a new token."""
    global ws, JWT
    JWT = fetch_jwt()
    log("CONNECT", f"opening WS → {WS_URL}")
    ws = websocket.create_connection(
        WS_URL,
        subprotocols=["pudgyprot", JWT],
        origin=ORIGIN,
        timeout=15,
    )
    ws.settimeout(RECV_TIMEOUT)
    log("CONNECT", "✅ WebSocket handshake successful — NO BROWSER INVOLVED")

try:
    connect(initial=True)
except Exception as e:
    log("FATAL", f"handshake failed: {e!r}")
    tg_send(f"🛑 Bot failed to start — handshake error: {e!r}")
    time.sleep(1.5); sys.exit(1)

# ===================== HELPERS =====================
def send(action: str, **fields):
    fields.update(action=action, reqMsgID=1, serverAck=0)
    raw = sign(fields)
    log("SEND ▶", f"{action}  {raw if PRINT_RAW_FRAMES else ''}"[:300])
    try:
        ws.send(raw)
    except (websocket.WebSocketConnectionClosedException, OSError, BrokenPipeError) as e:
        log("CLOSED", f"send failed: {e!r}")
        raise Reconnect()

class ServerError(Exception):
    def __init__(self, code, payload):
        super().__init__(code)
        self.code = code
        self.payload = payload

def recv_until(name: str, timeout: int = RECV_TIMEOUT):
    end = time.time() + timeout
    while time.time() < end:
        try:
            raw = ws.recv()
        except websocket.WebSocketTimeoutException:
            log("WAIT", f"no message yet (still waiting for {name})")
            continue
        except (websocket.WebSocketConnectionClosedException, OSError) as e:
            code   = getattr(ws, "close_code", None)
            reason = getattr(ws, "close_reason", None)
            log("CLOSED", f"⚠️  server closed connection. code={code} reason={reason!r}  ({e!r})")
            raise Reconnect()
        if not raw:
            continue
        try:
            j = json.loads(raw)
        except Exception:
            log("RECV ◀", f"<non-json> {raw[:150]}")
            continue

        tag = j.get("_action") or j.get("errorCode", {}).get("id") or "?"
        if PRINT_RAW_FRAMES:
            log("RECV ◀", f"{tag}  {raw[:300]}")
        else:
            log("RECV ◀", tag)

        if "errorCode" in j:
            err_id = j["errorCode"].get("id", "")
            log("ERROR", f"server error: {raw[:500]}")
            tg_send(f"⚠️ Server error: {err_id}\n{raw[:300]}")
            raise ServerError(err_id, j)
        if j.get("_action") == name:
            return j
    raise TimeoutError(f"didn't receive {name} within {timeout}s")


def buy_bait():
    """Send purchaseStoreItem and consume the ack(s) without crashing."""
    global pebbles, bait
    log("BUY", f"purchasing bait pack storeItemId={BAIT_STORE_ITEM_ID}")
    send("purchaseStoreItem", storeItemId=BAIT_STORE_ITEM_ID, currencyId=1)
    t0 = time.time()
    while time.time() - t0 < 5:
        try:
            raw = ws.recv()
        except websocket.WebSocketTimeoutException:
            break
        try:
            j = json.loads(raw)
        except Exception:
            continue
        log("RECV ◀", f"(buy) {raw[:300]}")
        if "errorCode" in j:
            log("FATAL", "purchase rejected — check BAIT_STORE_ITEM_ID / wallet")
            tg_send(f"🛑 Bot stopped — bait purchase rejected\n{raw[:300]}")
            time.sleep(1.5); sys.exit(1)
        if j.get("_action") in ("purchaseComplete","storePurchaseComplete",
                                "itemPurchased","purchaseResponse","walletUpdated",
                                "storeItemRewardsClaimed"):
            break
    bait    += 5
    pebbles -= 5
    log("BUY", f"+5 bait, -5 pebbles. bait={bait} pebbles={pebbles}")
    tg_send(f"🪱 Bought bait pack (+5 bait, -5 pebbles)\n💰 Pebbles: {pebbles}  🪱 Bait: {bait}")

# ===================== LOGIN =====================
def do_login():
    """Send login and wait for loginResponse. Returns the parsed message."""
    send("login")
    return recv_until("loginResponse")

login = do_login()

profile  = login.get("gameProfile", {})
name     = profile.get("penguin", {}).get("penguinName", "?")
wallet   = profile.get("wallet", {})
pebbles  = wallet.get("pebbles", 0)
seashells = wallet.get("seashells", 0)

# Try to read actual bait count from inventory (best-effort — adapt to real shape)
bait = 0
inv  = profile.get("inventory", {}).get("userInventory", {}) or {}
for k, v in inv.items():
    item = v.get("item", {}) if isinstance(v, dict) else {}
    if item.get("itemType") == "AwardableEnumBait" and item.get("referenceID") == BAIT_ID:
        bait = v.get("quantity", 0)
        break
if bait == 0:
    bait = 5  # fallback so we don't insta-buy
    log("WARN", "couldn't parse bait from inventory — assuming 5; will buy more on demand")

log("INFO", f"logged in as: {name}")
log("INFO", f"starting wallet: pebbles={pebbles}  seashells={seashells}  bait(id={BAIT_ID})~{bait}")
print("─" * 90, flush=True)

# ===================== MAIN LOOP =====================
caught_total   = 0
pebbles_gained = 0
xp_gained      = 0
loop_start     = time.time()

skipped_total       = 0
reconnect_count     = 0
RECONNECT_BACKOFF   = [1, 2, 5, 10, 15, 30, 60]  # seconds; clamps at last value

while True:
    try:
        if bait < 1:
            buy_bait()

        # Try to start fishing; if server says "no bait," buy and retry once.
        try:
            send("startFishing", holeId=HOLE_ID, baitId=BAIT_ID)
            started = recv_until("fishingStarted")
        except ServerError as e:
            if e.code == "ErrorCodeStartFishingHandlerInsufficientBait":
                log("RECOVER", "server says insufficient bait — buying and retrying")
                bait = 0
                buy_bait()
                send("startFishing", holeId=HOLE_ID, baitId=BAIT_ID)
                started = recv_until("fishingStarted")
            else:
                # Any other startFishing error → log, skip, retry next iteration.
                raise

        t = float(started.get("t", 8.0))
        bait -= 1
        log("WAIT", f"server timer t={t:.2f}s before catch is allowed")

        bite = recv_until("fishBite")
        fb   = bite.get("fishBite", {})
        fish_id, size, weight = fb.get("fishId"), fb.get("size"), fb.get("weight")
        log("BITE", f"server picked fishId={fish_id} size={size} weight={weight}")

        sleep_for = t + 0.3
        log("SLEEP", f"sleeping {sleep_for:.2f}s to satisfy server timer")
        time.sleep(sleep_for)

        send("fishCaught", fishId=fish_id, holeId=HOLE_ID)
        r = recv_until("fishRewarded")

        coins = sum(x.get("quantity", 0) for x in r.get("rewards", [])
                    if x.get("itemType") == "AwardableEnumCurrency")
        xp    = sum(x.get("quantity", 0) for x in r.get("rewards", [])
                    if x.get("itemType") == "AwardableEnumXp")
        pebbles        += coins
        pebbles_gained += coins
        xp_gained      += xp
        caught_total   += 1

        elapsed = time.time() - loop_start
        rate    = caught_total / (elapsed / 60.0) if elapsed > 0 else 0.0

        log("CATCH", f"✅ #{caught_total}  fish={fish_id}  +{coins} pebbles  +{xp} XP")
        log("STATS", f"running: pebbles_gained={pebbles_gained}  xp_gained={xp_gained}  "
                     f"bait_left={bait}  rate={rate:.2f}/min  elapsed={elapsed:.0f}s")
        print("─" * 90, flush=True)

        tg_send(f"✅ #{caught_total}  fish={fish_id}  +{coins} pebbles  +{xp} XP")
        if caught_total % TG_STATS_EVERY == 0:
            mm, ss = divmod(int(elapsed), 60); hh, mm = divmod(mm, 60)
            tg_send(
                f"📊 Stats\n"
                f"🎣 Caught: {caught_total}\n"
                f"💰 Pebbles gained: +{pebbles_gained} (balance {pebbles})\n"
                f"⭐ XP gained: +{xp_gained}\n"
                f"⚡ Rate: {rate:.2f}/min\n"
                f"⏱ Uptime: {hh:02d}:{mm:02d}:{ss:02d}\n"
                f"🪱 Bait left: {bait}"
            )

    except ServerError as e:
        skipped_total += 1
        log("SKIP", f"⚠️  iteration skipped — server error {e.code}  (total skipped: {skipped_total})")
        tg_send(f"⚠️ Skipped catch — server error: {e.code}  (skipped total: {skipped_total})")
        time.sleep(1.0)   # brief breather so we don't hammer the server on repeated errors
        continue

    except TimeoutError as e:
        skipped_total += 1
        log("SKIP", f"⚠️  iteration skipped — server silent ({e})  (total skipped: {skipped_total})")
        tg_send(f"⚠️ Skipped catch — server timeout  (skipped total: {skipped_total})")
        time.sleep(1.0)
        continue

    except Reconnect:
        # Socket died (Cloudflare idle close, server restart, network blip).
        # Reopen and re-login, then continue the loop with state preserved.
        reconnect_count += 1
        delay = RECONNECT_BACKOFF[min(reconnect_count - 1, len(RECONNECT_BACKOFF) - 1)]
        log("RECONNECT", f"♻️  socket dropped — reconnect #{reconnect_count} in {delay}s")
        tg_send(f"♻️ Reconnecting #{reconnect_count} (delay {delay}s)")
        try: ws.close()
        except Exception: pass
        time.sleep(delay)
        try:
            connect()
            do_login()
            log("RECONNECT", "✅ re-logged in, resuming fishing")
            tg_send(f"✅ Reconnected #{reconnect_count} — resuming")
        except Exception as e:
            log("RECONNECT", f"failed: {e!r} — will retry on next loop")
            # Fall through; next iteration will hit Reconnect again and back off.
        continue
