"""
PudgyWorld multi-account orchestrator — *architectural demo* only.

What this teaches you:
  - How a token manager handles JWT refresh transparently
  - How N independent fishing workers share state safely
  - How an aggregator surfaces fleet-wide stats

What this DELIBERATELY does NOT do (you'd add these to weaponize it):
  - No automated account creation
  - No proxy rotation (1000 connections from one IP = instant Cloudflare ban)
  - No password-based login automation (only token refresh; if both expire,
    you re-paste the JWT manually, like in bot.py)
  - No distributed runner (single process only)

Use it with 2–5 of YOUR OWN test accounts to see the fleet pattern in action.

Setup:
  pip install websocket-client
  Create accounts.json (see template below).
  python orchestrator.py
"""

import websocket, json, hmac, hashlib, base64, time, threading, urllib.request, urllib.parse, ssl, os, sys, re, random
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import requests
from datetime import datetime, timezone

# Full-flow Ory re-login (replaces broken refresh_token grant). Silenced.
import jwtharvest
jwtharvest.VERBOSE = False

# ===================== CONFIG =====================
KEY     = b"wB7FLqHISDjBxCaklTFafvUpacahD5ocMORUkR+PpJI="
WS_URL  = "wss://pudgyworld.pudgyworld.com/ws?ver=0.8.4&g=1"
ORIGIN  = "https://play.pudgyworld.com"
TOKEN_URL = "https://auth-ory.pudgyworld.com/oauth2/token"
CLIENT_ID = "098775a4-000a-4382-a726-5df3204d5840"
HOLE_ID = 11
BAIT_ID = 1
BAIT_STORE_ITEM_ID = 18
ACCOUNTS_FILE = "accounts.json"
STATS_INTERVAL = 30   # seconds between aggregate stats prints

# ---- Token refresh tuning ----
# Refresh anything whose access_expires_at is within this many seconds of now.
REFRESH_BUFFER = 360
# How often the background refresher sweeps the fleet.
REFRESH_SWEEP_INTERVAL = 60
# Concurrent login flows. Each is a few HTTP round-trips to Ory; 50 is fast and
# polite. Bump to ~100 if Ory tolerates it, drop if you start seeing 429s.
REFRESH_CONCURRENCY = 10

# ---- Fishing pacing ----
# Sleep between a successful fishCaught and the next startFishing. Set both to
# 0 to fire the next cast as fast as the server allows (current behavior). For
# jitter pick a range, e.g. MIN=1.0 MAX=3.5.
FISHING_DELAY_MIN = 0.0
FISHING_DELAY_MAX = 0.0

# ---- Reconnect backoff ----
# Normal-case wait after a disconnect. Limited-tier proxies tear the tunnel
# every ~30s — those expected drops shouldn't trip any safety net.
RECONNECT_WAIT_MIN_SEC      = 2.0
RECONNECT_WAIT_MAX_SEC      = 5.0
# A session that lived this long is treated as "ran fine, then the proxy
# rotated" — does NOT count as a consecutive failure.
HEALTHY_SESSION_SEC         = 10.0
# After this many consecutive short-lived sessions (session_duration <
# HEALTHY_SESSION_SEC), assume the server / proxy is genuinely sick and
# escalate the backoff so we don't hammer a dead endpoint.
RECONNECT_ESCALATE_AFTER    = 5
RECONNECT_ESCALATE_MAX_SEC  = 60.0

# ---- Daily farming limit ----
# Total wall-clock hours the fleet is allowed to fish in one process run.
# Once reached, every worker stops cleanly after its current cycle and the
# process stays up (so Ctrl+C summary, Telegram, and the aggregator still
# work). Set to 0 to disable the limit entirely.
FARMING_HOURS_PER_DAY = 12

# Set when the daily limit is hit; every worker checks this at the top of its
# fishing loop and exits gracefully.
STOP_FARMING = threading.Event()

# ---- Proxy health check + backup pool ----
# File the backup pool is sourced from. Same format register.py expects:
# `scheme://host:port:user:pass` per line. On startup we load every entry and
# drop the ones already pinned to an account in accounts.json (so backups are
# strictly "unused" proxies). When a worker's assigned proxy fails the probe
# below, it claims the next live backup from this pool and updates
# accounts.json so future sessions/process restarts keep the new mapping.
BACKUP_PROXIES_FILE = "proxies.txt"
# IP-echo service: returns {"ip":"<egress ip>"}. We GET it through the proxy
# and treat anything that parses as a valid IPv4/IPv6 string as "proxy works".
# Doubles as confirmation that the proxy is actually forwarding (not just
# returning a 200 from a captive portal / pudgy edge that the proxy can hit).
PROXY_PROBE_URL     = "https://api.ipify.org?format=json"
PROXY_PROBE_TIMEOUT = 10  # seconds — some shared proxies are slow on first hit

# Strict pre-flight: before any worker starts we probe every assigned proxy
# AND every backup. If any account's proxy is dead/missing AND the live
# backup count can't cover the shortfall, we refuse to launch. Prevents the
# silent "connected (proxy=none)" fallback when proxies actually broke.
# Set False to skip the check (legacy behavior — workers go direct on failure).
STRICT_PROXY_PREFLIGHT       = False
PROXY_PREFLIGHT_CONCURRENCY  = 50  # parallel probe workers

_backup_proxies: list[str] = []
_backup_lock = threading.Lock()

_SSL = ssl.create_default_context(); _SSL.check_hostname = False; _SSL.verify_mode = ssl.CERT_NONE

# ===================== TELEGRAM =====================
TG_BOT_TOKEN  = "8991199892:AAFUWF35cOw-FMWLTOdNVkR2x44cNTu5ZMg"
TG_CHAT_ID    = "769594408"
# Per-catch pings spam Telegram fast (per chat the API caps ~20 msg/min ->
# 429s). False = aggregator handles fleet-level updates. Recommended off
# once you have more than one worker or proxies stable enough to fire
# catches every ~7s.
TG_PER_CATCH  = False
# Hard floor between any two sendMessage calls so bursts get dropped rather
# than queued into 429s. 3.5s = ~17/min, comfortably under Telegram's 20/min
# per-chat cap with safety margin.
TG_MIN_INTERVAL_SEC = 3.5

_tg_last_sent = {}
_tg_lock = threading.Lock()
_tg_last_global_send = [0.0]   # mutable holder for last-send timestamp

def tg_send(text: str, dedupe_key: str = None, dedupe_seconds: int = 60):
    """Fire-and-forget Telegram notification. Two anti-spam gates:
      - dedupe_key + dedupe_seconds: suppress identical-category bursts
      - TG_MIN_INTERVAL_SEC: hard floor between ANY two sends, to stay
        under Telegram's per-chat rate limit. Messages that hit the floor
        are DROPPED (not queued) — caller's flow is never blocked."""
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    now = time.time()
    if dedupe_key:
        with _tg_lock:
            last = _tg_last_sent.get(dedupe_key, 0)
            if now - last < dedupe_seconds:
                return
            _tg_last_sent[dedupe_key] = now
    # Global rate-limit gate — dropping is intentional. If you need every
    # catch logged, look at stdout; Telegram is for human-facing pings.
    with _tg_lock:
        if now - _tg_last_global_send[0] < TG_MIN_INTERVAL_SEC:
            return
        _tg_last_global_send[0] = now
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
                context=_SSL,
            ).read()
        except Exception as e:
            print(f"[tg] send failed: {e!r}", flush=True)
    threading.Thread(target=_go, daemon=True).start()

# ===================== ACCOUNT STORE =====================
# accounts.json format:
# [
#   {
#     "label": "alt1",
#     "access_token": "eyJ...",
#     "refresh_token": "ory_rt_...",
#     "access_expires_at": 1779769154        ← unix ts; 0 means unknown
#   },
#   ...
# ]
accounts_lock = threading.Lock()

def load_accounts():
    """Read accounts.json. If it's missing or empty, seed it with stub entries
    for every label found in credentials.txt — bulk_refresh() will then fill in
    real tokens on first startup."""
    accs = []
    if os.path.exists(ACCOUNTS_FILE):
        try:
            with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
                accs = json.load(f) or []
        except (json.JSONDecodeError, ValueError):
            # Empty file or malformed JSON — treat as fresh start.
            print(f">> {ACCOUNTS_FILE} is empty/invalid; will rebuild from credentials.txt",
                  flush=True)
            accs = []

    try:
        creds = jwtharvest.load_credentials_map()
    except FileNotFoundError:
        if not accs:
            print(f"X neither {ACCOUNTS_FILE} nor credentials.txt has any accounts.")
            sys.exit(1)
        return accs

    known = {a["label"] for a in accs}
    added = []
    for label in creds:
        if label == "__default__" or label in known:
            continue
        accs.append({
            "label": label,
            "access_token": "",
            "refresh_token": "",
            "access_expires_at": 0,
        })
        added.append(label)

    if added:
        print(f">> seeded {len(added)} new account(s) from credentials.txt: {added[:10]}"
              f"{'...' if len(added) > 10 else ''}", flush=True)
        with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
            json.dump(accs, f, indent=2)

    if not accs:
        print(f"X no accounts. Add lines to credentials.txt (label:email:password).")
        sys.exit(1)
    return accs

def save_accounts(accs):
    with accounts_lock:
        with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
            json.dump(accs, f, indent=2)

# ===================== TOKEN MANAGER =====================
def jwt_exp(token):
    """Read the `exp` claim from a JWT without verifying the signature.
    Returns unix-timestamp int, or 0 if it can't be parsed."""
    try:
        payload_b64 = token.split(".")[1]
        # JWT uses base64-url WITHOUT padding; add it back.
        padding = "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
        return int(payload.get("exp", 0))
    except Exception:
        return 0

def jwt_seconds_left(token):
    return max(0, jwt_exp(token) - int(time.time()))

def _needs_refresh(account, skew=REFRESH_BUFFER):
    """True if the account has no token, an unparseable one, or one expiring soon."""
    tok = account.get("access_token") or ""
    if not tok:
        return True
    exp = jwt_exp(tok) or int(account.get("access_expires_at") or 0)
    return exp - int(time.time()) < skew


def _refresh_one(account):
    """Worker for the thread pool: full Ory re-login for one account, in-place.
    Returns (label, ok, error_message)."""
    label = account["label"]
    try:
        jwtharvest.refresh_account_inplace(account)
        return (label, True, None)
    except jwtharvest.LoginError as e:
        return (label, False, f"{e.kind}: {e}")
    except KeyError as e:
        return (label, False, f"no credentials in credentials.txt: {e}")
    except Exception as e:
        return (label, False, f"{type(e).__name__}: {e}")


def bulk_refresh(accounts, skew=REFRESH_BUFFER, max_workers=REFRESH_CONCURRENCY,
                 force=False, label_prefix="bulk"):
    """
    Refresh every account that needs it, in parallel. Writes accounts.json
    exactly once at the end (regardless of fleet size). Returns dict of
    failures: {label: reason}. Successes are silent except for a summary log.
    """
    pending = [a for a in accounts if force or _needs_refresh(a, skew)]
    if not pending:
        return {}

    t0 = time.time()
    active = min(len(pending), max_workers)
    print(f">> [{label_prefix}] refreshing {len(pending)}/{len(accounts)} "
          f"account(s) ({active} in parallel, cap={max_workers})...", flush=True)

    failures = {}
    completed = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_refresh_one, a) for a in pending]
        for fut in as_completed(futures):
            label, ok, err = fut.result()
            completed += 1
            if not ok:
                failures[label] = err
                print(f"  FAIL [{label}] {err}", flush=True)
            # Light progress for large fleets:
            if completed % 100 == 0:
                print(f"  ... {completed}/{len(pending)}", flush=True)

    # Single file write for the whole batch — fast even at 10k accounts.
    save_accounts(accounts)

    elapsed = time.time() - t0
    ok_count = len(pending) - len(failures)
    print(f">> [{label_prefix}] {ok_count} refreshed, {len(failures)} failed "
          f"in {elapsed:.1f}s ({ok_count / max(elapsed, 0.001):.1f}/s)", flush=True)
    if failures:
        tg_send(
            f"⚠️ {len(failures)} account(s) failed to refresh:\n" +
            "\n".join(f"• {l}: {r}" for l, r in list(failures.items())[:20]),
            dedupe_key="refresh_failures", dedupe_seconds=300,
        )
    return failures


def refresher_loop(accounts):
    """Background daemon: sweep the fleet every REFRESH_SWEEP_INTERVAL seconds
    and refresh anything inside the REFRESH_BUFFER window. All refreshes for
    a given sweep run in parallel."""
    while True:
        time.sleep(REFRESH_SWEEP_INTERVAL)
        try:
            bulk_refresh(accounts, label_prefix="sweep")
        except Exception as e:
            print(f"[refresher] sweep failed: {e!r}", flush=True)


def get_valid_jwt(account):
    """Worker-side, single-account guarantee: if for some reason the background
    sweeper hasn't refreshed this one yet (e.g. just-spawned worker), do it
    synchronously now. Cheap when token is still valid."""
    if not _needs_refresh(account):
        return account["access_token"]
    jwtharvest.refresh_account_inplace(account)
    save_accounts(ALL_ACCOUNTS)   # single-account write, rare path
    print(f"[{account['label']}] synchronous refresh OK -- new JWT valid for "
          f"{jwt_exp(account['access_token']) - int(time.time())}s", flush=True)
    return account["access_token"]

# ===================== PROXY-AWARE WS =====================
# Idle CONNECT-proxy sockets (and Cloudflare in general) get reaped if the
# WS goes quiet — that looks like a random mid-fishing disconnect even
# though we're actively catching. A 20s WS-level ping keeps the TCP alive.
WS_PING_INTERVAL_SEC = 20


def _ws_connect(jwt, proxy_url):
    """Open the fishing WebSocket, optionally routed through `proxy_url`
    (requests-style http://user:pass@host:port). One proxy per account is
    already enforced upstream by register.py (account['proxy_raw']), so this
    function just plumbs whatever the account dict has into websocket-client.
    Starts a background WS ping thread to keep the proxy's TCP slot warm so
    we don't get idle-closed mid-fishing. Returns the connected socket;
    raises on a bad proxy URL."""
    kwargs = dict(
        subprotocols=["pudgyprot", jwt],
        origin=ORIGIN,
        timeout=15,
        enable_multithread=True,
    )
    if proxy_url:
        m = re.match(r"^(https?)://(?:([^:]+):([^@]+)@)?([^:/]+):(\d+)$", proxy_url)
        if not m:
            raise RuntimeError(f"bad proxy url for websocket: {proxy_url!r}")
        scheme, user, pw, host, port = m.group(1), m.group(2), m.group(3), m.group(4), int(m.group(5))
        kwargs["http_proxy_host"] = host
        kwargs["http_proxy_port"] = port
        kwargs["proxy_type"]      = scheme
        if user:
            kwargs["http_proxy_auth"] = (user, pw)
    ws = websocket.create_connection(WS_URL, **kwargs)

    # Background pinger. Daemon thread, dies with the process / when the
    # socket goes away. Stop flag stashed on the ws so we can shut it down
    # cleanly from the worker if needed.
    stop_flag = threading.Event()
    def _pinger():
        while not stop_flag.is_set():
            if stop_flag.wait(WS_PING_INTERVAL_SEC):
                return
            try:
                ws.ping()
            except Exception:
                return
    t = threading.Thread(target=_pinger, daemon=True)
    t.start()
    ws._pinger_stop = stop_flag  # type: ignore[attr-defined]
    return ws


def mask_proxy(proxy_url):
    """Hide password for log lines."""
    if not proxy_url:
        return None
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", proxy_url)


def _parse_proxies_file(path: str) -> list[str]:
    """Read BACKUP_PROXIES_FILE → list of requests-style proxy URLs
    (`scheme://user:pass@host:port`). Same accepted formats as
    register.load_proxies(): with or without a leading `scheme://`
    (defaults to http when missing)."""
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "://" not in line:
            line = "http://" + line
        scheme, rest = line.split("://", 1)
        parts = rest.split(":")
        if len(parts) != 4:
            continue
        host, port, user, pw = parts
        out.append(f"{scheme}://{user}:{pw}@{host}:{port}")
    return out


def load_backup_pool(accounts):
    """Populate `_backup_proxies` with every proxy in BACKUP_PROXIES_FILE that
    is NOT already pinned to an account, so backups are strictly unused."""
    global _backup_proxies
    all_proxies = _parse_proxies_file(BACKUP_PROXIES_FILE)
    assigned = {a.get("proxy_raw") for a in accounts if a.get("proxy_raw")}
    with _backup_lock:
        _backup_proxies = [p for p in all_proxies if p not in assigned]
    print(f">> backup proxy pool: {len(_backup_proxies)} unused "
          f"(of {len(all_proxies)} in {BACKUP_PROXIES_FILE})", flush=True)


def claim_backup_proxy() -> str | None:
    """Pop one backup off the pool under lock so two workers never grab the
    same backup. Returns None when the pool is exhausted."""
    with _backup_lock:
        if not _backup_proxies:
            return None
        return _backup_proxies.pop(0)


def _normalize_proxy_url(url: str | None) -> str | None:
    """Accept either of:
        scheme://user:pass@host:port       (requests-style — already correct)
        [scheme://]host:port:user:pass     (raw 4-colon — converts to the above)
    Returns the requests-style form, or None if `url` is empty/garbage.
    Robust so we don't blow up on legacy account['proxy_raw'] entries that
    were written before register.load_proxies was fixed."""
    if not url:
        return None
    s = url.strip()
    if not s:
        return None
    if "://" not in s:
        s = "http://" + s
    scheme, rest = s.split("://", 1)
    # Already in user:pass@host:port form? leave it.
    if "@" in rest:
        return s
    parts = rest.split(":")
    if len(parts) == 4:
        host, port, user, pw = parts
        return f"{scheme}://{user}:{pw}@{host}:{port}"
    return s  # unknown shape — pass through; probe will fail and we rotate


def probe_proxy(proxy_url: str | None) -> bool:
    """Verify the proxy actually forwards traffic by hitting an IP-echo
    service through it and confirming the response parses as a real IP.
    Catches three failure modes the old health-endpoint probe missed:
      - malformed proxy URL (requests silently ignores)
      - proxy returns a 200 but is a captive portal / interception
      - probe target itself is down or geo-blocks the proxy
    None proxy = direct connection, nothing to probe -> True."""
    if not proxy_url:
        return True
    try:
        r = requests.get(
            PROXY_PROBE_URL,
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=PROXY_PROBE_TIMEOUT,
        )
        if not r.ok:
            return False
        ip = (r.json() or {}).get("ip", "")
        # Trivial sanity: at least one dot (IPv4) or one colon (IPv6).
        return bool(ip) and ("." in ip or ":" in ip)
    except Exception:
        return False


def ensure_working_proxy(account, log) -> str | None:
    """Probe `account['proxy_raw']`. Three cases:
      1) Has a working proxy → use it.
      2) Has a dead/malformed proxy → claim live backups until one passes.
      3) Has NO proxy assigned (legacy entry from when register.py couldn't
         parse proxies.txt) → also claim from the backup pool so we don't
         silently go direct while unused proxies sit idle.
    Persists swaps + one-time URL normalization to accounts.json."""
    raw   = account.get("proxy_raw")
    proxy = _normalize_proxy_url(raw)
    # Heal a stored value in the legacy raw 4-colon shape — otherwise the
    # probe would keep failing forever and we'd burn through every backup.
    if proxy and proxy != raw:
        log(f"   .. normalized stored proxy URL")
        account["proxy_raw"] = proxy
        save_accounts(ALL_ACCOUNTS)
    # Case 1: assigned proxy works → done.
    if proxy and probe_proxy(proxy):
        return proxy
    # Case 3: no proxy assigned at all → only try to claim a backup if the
    # pool is non-empty; otherwise stay direct (existing behavior).
    if proxy is None:
        with _backup_lock:
            pool_has_entries = bool(_backup_proxies)
        if not pool_has_entries:
            return None
        log("   .. no proxy assigned but backup pool has entries — claiming one")
    else:
        log(f"❗ assigned proxy failed probe ({mask_proxy(proxy)}); rotating")
    while True:
        backup = claim_backup_proxy()
        if backup is None:
            log("⚠️ backup pool exhausted — connecting direct")
            new_proxy = None
            break
        if probe_proxy(backup):
            log(f"✓ rotated to backup proxy {mask_proxy(backup)}")
            new_proxy = backup
            break
        log(f"   .. backup {mask_proxy(backup)} also dead — trying next")
    account["proxy_raw"] = new_proxy
    save_accounts(ALL_ACCOUNTS)
    tg_send(
        f"🔀 [{account['label']}] proxy rotated to "
        f"{mask_proxy(new_proxy) if new_proxy else 'direct'}",
        dedupe_key=f"proxy_rotate:{account['label']}", dedupe_seconds=300,
    )
    return new_proxy


def preflight_proxies(accounts) -> bool:
    """Probe every account's assigned proxy AND every backup pool entry
    concurrently before any worker starts. Three outcomes:

      - All assigned proxies alive → return True (best case).
      - Some assigned dead/missing, but live backups >= shortfall → return
        True; ensure_working_proxy() will rotate them during normal flow.
      - Live backups < shortfall → print the gap and return False so main
        aborts. Prevents silent "(proxy=none)" fallbacks.

    Side effects:
      - Legacy raw 4-colon proxy URLs in accounts.json are normalized in
        place and the file is rewritten.
      - Dead backups are pruned from the shared pool so workers never claim
        a known-dead one.
    """
    if not STRICT_PROXY_PREFLIGHT:
        return True

    print(">> proxy preflight: probing assigned + backup proxies in parallel...", flush=True)
    t0 = time.time()

    # --- 1) Probe all assigned proxies. Normalize legacy URLs along the way.
    def _check_assigned(a):
        raw  = a.get("proxy_raw")
        norm = _normalize_proxy_url(raw)
        if norm and norm != raw:
            a["proxy_raw"] = norm   # heal in place; caller saves
        # None = "no proxy assigned" — counts as needing a backup, not alive.
        ok = bool(norm) and probe_proxy(norm)
        return (a.get("label"), norm, ok)

    with ThreadPoolExecutor(max_workers=min(PROXY_PREFLIGHT_CONCURRENCY,
                                            max(1, len(accounts)))) as pool:
        assigned_results = list(pool.map(_check_assigned, accounts))

    dead_or_missing = [(l, p) for (l, p, ok) in assigned_results if not ok]
    alive_assigned  = len(assigned_results) - len(dead_or_missing)

    # --- 2) Probe the backup pool. Drop any dead entries from the live pool.
    with _backup_lock:
        backups_snapshot = list(_backup_proxies)

    if backups_snapshot:
        with ThreadPoolExecutor(max_workers=min(PROXY_PREFLIGHT_CONCURRENCY,
                                                len(backups_snapshot))) as pool:
            backup_results = list(pool.map(
                lambda p: (p, probe_proxy(p)), backups_snapshot))
    else:
        backup_results = []

    live_backups = [p for (p, ok) in backup_results if ok]
    dead_backups = {p for (p, ok) in backup_results if not ok}

    if dead_backups:
        with _backup_lock:
            _backup_proxies[:] = [p for p in _backup_proxies if p not in dead_backups]

    # Persist any healed proxy_raw fields once.
    save_accounts(accounts)

    elapsed = time.time() - t0
    print(f">> preflight: {alive_assigned}/{len(assigned_results)} assigned alive, "
          f"{len(live_backups)}/{len(backup_results)} backups alive "
          f"({elapsed:.1f}s)", flush=True)

    need = len(dead_or_missing)
    have = len(live_backups)
    if need == 0:
        return True
    if have >= need:
        print(f">> preflight OK: {need} account(s) need rotation, "
              f"{have} live backup(s) available", flush=True)
        return True

    bad_labels = [l for (l, _) in dead_or_missing][:20]
    print(f"!! preflight FAILED: {need} account(s) need a working proxy but "
          f"only {have} live backup(s) in the pool. Refusing to start.", flush=True)
    print(f"   dead/missing labels: {bad_labels}"
          f"{' ...' if len(dead_or_missing) > 20 else ''}", flush=True)
    print(f"   add more entries to {BACKUP_PROXIES_FILE} (need at least "
          f"{need - have} more live) or set STRICT_PROXY_PREFLIGHT=False to "
          f"let workers go direct.", flush=True)
    tg_send(
        f"⛔ Orchestrator NOT starting: need {need} proxies, "
        f"only {have} live in backup pool",
        dedupe_key="preflight_fail", dedupe_seconds=300,
    )
    return False


# ===================== DAILY LIMIT WATCHER =====================
def daily_limit_watcher(start_time):
    """Background daemon: once FARMING_HOURS_PER_DAY of wall time elapses, set
    STOP_FARMING so every worker exits cleanly after its current cycle."""
    if FARMING_HOURS_PER_DAY <= 0:
        return  # disabled
    deadline = start_time + FARMING_HOURS_PER_DAY * 3600
    while not STOP_FARMING.is_set():
        remaining = deadline - time.time()
        if remaining <= 0:
            STOP_FARMING.set()
            msg = (f">> daily farming limit reached "
                   f"({FARMING_HOURS_PER_DAY}h) — workers will stop after current cycle")
            print(msg, flush=True)
            tg_send(f"🛑 Daily farming limit ({FARMING_HOURS_PER_DAY}h) reached — workers stopping")
            return
        # Sleep in 60s chunks so a shutdown signal isn't bottled up here.
        time.sleep(min(remaining, 60))


# ===================== SIGNING =====================
def sign(payload):
    now = datetime.now(timezone.utc)
    payload["time"] = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    canon = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload["sig"] = base64.b64encode(hmac.new(KEY, canon.encode(), hashlib.sha256).digest()).decode()
    return json.dumps(payload, sort_keys=True)

# ===================== WORKER =====================
class FisherWorker(threading.Thread):
    def __init__(self, account, shared_stats):
        super().__init__(daemon=True)
        self.account = account
        self.label   = account["label"]
        self.stats   = shared_stats[self.label] = {
            "caught": 0, "pebbles_gained": 0, "xp_gained": 0,
            "skipped": 0, "reconnects": 0, "state": "starting", "bait": 0,
            "pebbles": 0,   # live balance (login_balance + pebbles_gained - bait_spent)
        }

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{ts}] [{self.label}] {msg}", flush=True)

    def run(self):
        # Counts only SHORT-LIVED failures in a row. Sessions that ran at
        # least HEALTHY_SESSION_SEC are treated as "worked fine, then the
        # proxy rotated" and reset this back to 0.
        consecutive_fails = 0
        while not STOP_FARMING.is_set():
            session_start = time.time()
            try:
                self._session()
            except jwtharvest.LoginError as e:
                # Auth failure — always counts as a real failure regardless
                # of timing, since we never got past login.
                consecutive_fails += 1
                self.stats["state"] = f"login failed ({e.kind})"
                self.log(f"⛔ login failed: {e} — retrying in 5 min")
                tg_send(
                    f"⛔ [{self.label}] login failed: {e.kind}: {e}",
                    dedupe_key=f"login_fail:{self.label}",
                    dedupe_seconds=600,
                )
                # Wake early if the daily limit fires while we're backing off.
                STOP_FARMING.wait(300)
            except Exception as e:
                self.stats["reconnects"] += 1
                self.stats["state"] = f"reconnecting ({type(e).__name__})"
                duration = time.time() - session_start
                if duration >= HEALTHY_SESSION_SEC:
                    # Normal mid-flow drop (limited-proxy tunnel cycle, idle
                    # close, etc.). Doesn't indicate trouble.
                    consecutive_fails = 0
                else:
                    consecutive_fails += 1

                wait = random.uniform(RECONNECT_WAIT_MIN_SEC, RECONNECT_WAIT_MAX_SEC)
                if consecutive_fails >= RECONNECT_ESCALATE_AFTER:
                    # Sustained short-lived failures → likely server-side or
                    # auth problem. Back off harder so we don't hammer.
                    wait = min(RECONNECT_ESCALATE_MAX_SEC, wait * 4)
                    self.log(f"⚠️  {consecutive_fails} short sessions in a row — "
                             f"extending backoff to {wait:.1f}s")

                self.log(f"♻️  session died after {duration:.1f}s: {e!r} — "
                         f"backing off {wait:.1f}s")
                tg_send(
                    f"♻️ [{self.label}] session died: {e!r} — reconnect #{self.stats['reconnects']}",
                    dedupe_key=f"reconnect:{self.label}",
                    dedupe_seconds=60,
                )
                STOP_FARMING.wait(wait)
        self.stats["state"] = "stopped (daily limit)"
        self.log("⏹ daily limit reached — worker stopped")

    def _session(self):
        jwt = get_valid_jwt(self.account)
        # Probe the pinned proxy; if dead, rotate to a backup before opening
        # the WS. ensure_working_proxy persists the swap to accounts.json.
        proxy = ensure_working_proxy(self.account, self.log)
        ws    = _ws_connect(jwt, proxy)
        ws.settimeout(20)
        self.stats["state"] = "connected"
        self.log(f"connected (proxy={mask_proxy(proxy) or 'none'})")

        def send(action, **fields):
            fields.update(action=action, reqMsgID=1, serverAck=0)
            ws.send(sign(fields))

        def recv_until(name):
            while True:
                raw = ws.recv()
                if not raw: continue
                j = json.loads(raw)
                if "errorCode" in j:
                    raise RuntimeError(f"server error: {j['errorCode'].get('id')}")
                if j.get("_action") == name:
                    return j

        # login
        send("login")
        login = recv_until("loginResponse")
        wallet = login.get("gameProfile", {}).get("wallet", {})
        self.stats["pebbles"] = wallet.get("pebbles", 0)
        self.stats["state"]   = "fishing"

        bait = 5  # assumption; you could parse inventory like bot.py does
        self.stats["bait"] = bait

        while True:
            # Daily limit hit — close the socket and let run() exit cleanly.
            if STOP_FARMING.is_set():
                try: ws.close()
                except Exception: pass
                return

            # Proactive refresh check before each fishing cycle.
            if jwt_seconds_left(self.account["access_token"]) < REFRESH_BUFFER:
                self.log(f"JWT about to expire ({jwt_seconds_left(self.account['access_token'])}s) — reconnecting with fresh token")
                try: ws.close()
                except Exception: pass
                return

            if bait < 1:
                send("purchaseStoreItem", storeItemId=BAIT_STORE_ITEM_ID, currencyId=1)
                ws.recv()  # ack (any frame)
                bait += 5
                self.stats["pebbles"] -= 5
                tg_send(f"🪱 [{self.label}] bought bait pack (+5 bait, -5 pebbles)  bal={self.stats['pebbles']}")

            try:
                send("startFishing", holeId=HOLE_ID, baitId=BAIT_ID)
                started = recv_until("fishingStarted")
            except RuntimeError as e:
                if "InsufficientBait" in str(e):
                    bait = 0; continue
                self.stats["skipped"] += 1; time.sleep(1); continue

            bait -= 1; self.stats["bait"] = bait
            t = float(started.get("t", 8.0))
            cycle_start = time.time()
            t_started   = time.time()

            bite = recv_until("fishBite")
            t_bite      = time.time()
            fish_id     = bite["fishBite"]["fishId"]

            # EXPERIMENT: skip the redundant sleep — fishBite only arrives
            # AFTER the server timer elapsed, so fishCaught right after should
            # be accepted.  If you see InvalidFishCaught / similar in the SKIP
            # log, set FAST_CATCH=False and we go back to sleeping t+0.3.
            FAST_CATCH = True
            if FAST_CATCH:
                pass  # send fishCaught immediately
            else:
                time.sleep(t + 0.3)
            t_sleep_end = time.time()

            send("fishCaught", fishId=fish_id, holeId=HOLE_ID)
            r = recv_until("fishRewarded")
            t_caught    = time.time()
            coins = sum(x.get("quantity", 0) for x in r.get("rewards", []) if x.get("itemType") == "AwardableEnumCurrency")
            xp    = sum(x.get("quantity", 0) for x in r.get("rewards", []) if x.get("itemType") == "AwardableEnumXp")
            self.stats["caught"]         += 1
            self.stats["pebbles_gained"] += coins
            self.stats["xp_gained"]      += xp
            self.stats["pebbles"]        += coins
            cycle_total = t_caught - cycle_start
            bite_wait   = t_bite - t_started
            sleep_wait  = t_sleep_end - t_bite
            catch_rtt   = t_caught - t_sleep_end
            self.log(
                f"✅ #{self.stats['caught']:<3d} fish={fish_id:<3d} "
                f"+{coins:>2d} pebbles +{xp:>2d} XP  bait={bait}  bal={self.stats['pebbles']}  "
                f"| server_t={t:.2f}s  bite_wait={bite_wait:.2f}s  "
                f"sleep={sleep_wait:.2f}s  catch_rtt={catch_rtt:.2f}s  "
                f"CYCLE={cycle_total:.2f}s"
            )
            if TG_PER_CATCH:
                tg_send(f"✅ [{self.label}] #{self.stats['caught']}  fish={fish_id}  +{coins}p +{xp}xp  bal={self.stats['pebbles']}")

            # Configurable inter-cycle pacing. Default (0/0) preserves the
            # original "as fast as the server allows" behavior. STOP_FARMING.wait
            # so the sleep is interruptible when the daily limit fires.
            if FISHING_DELAY_MAX > 0:
                delay = random.uniform(FISHING_DELAY_MIN, FISHING_DELAY_MAX)
                if STOP_FARMING.wait(delay):
                    try: ws.close()
                    except Exception: pass
                    return

# ===================== AGGREGATOR =====================
def _fmt_uptime(seconds):
    h, rem = divmod(int(seconds), 3600)
    m, s   = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

def aggregator(stats, start_time):
    while True:
        time.sleep(STATS_INTERVAL)
        elapsed = time.time() - start_time
        total_c = sum(s["caught"]         for s in stats.values())
        total_p = sum(s["pebbles_gained"] for s in stats.values())
        total_x = sum(s["xp_gained"]      for s in stats.values())
        total_s = sum(s["skipped"]        for s in stats.values())
        total_r = sum(s["reconnects"]     for s in stats.values())
        rate    = total_c / (elapsed / 60.0) if elapsed > 0 else 0

        print()
        print("╔══════════════════════════════════════════════════════════════════════════════════╗")
        print(f"║  📊 FLEET REPORT   uptime {_fmt_uptime(elapsed)}   workers {len(stats)}"
              f"   rate {rate:.2f}/min".ljust(83) + "║")
        print(f"║  caught={total_c}   pebbles=+{total_p}   xp=+{total_x}"
              f"   skipped={total_s}   reconnects={total_r}".ljust(83) + "║")
        print("╠══════════════════════╤════════╤════════════╤════════╤════════╤═══════════════════╣")
        print("║ worker               │ caught │   pebbles  │  bait  │ skipped│ state             ║")
        print("╠══════════════════════╪════════╪════════════╪════════╪════════╪═══════════════════╣")
        for label, s in stats.items():
            print(f"║ {label[:20]:<20s} │ {s['caught']:>6d} │ "
                  f"{s['pebbles']:>4d} (+{s['pebbles_gained']:<3d}) │ "
                  f"{s['bait']:>6d} │ {s['skipped']:>6d} │ {s['state'][:17]:<17s} ║")
        print("╚══════════════════════╧════════╧════════════╧════════╧════════╧═══════════════════╝")
        print()

        # Telegram fleet summary
        per_worker = "\n".join(
            f"   • {label}: caught={s['caught']}  bal={s['pebbles']} (+{s['pebbles_gained']})  bait={s['bait']}"
            for label, s in stats.items()
        )
        tg_send(
            f"📊 FLEET REPORT  uptime {_fmt_uptime(elapsed)}  workers {len(stats)}  rate {rate:.2f}/min\n"
            f"caught={total_c}  pebbles=+{total_p}  xp=+{total_x}  skipped={total_s}  reconnects={total_r}\n"
            f"{per_worker}"
        )

# ===================== MAIN =====================
if __name__ == "__main__":
    ALL_ACCOUNTS = load_accounts()
    print(f"▶ orchestrator: {len(ALL_ACCOUNTS)} accounts loaded", flush=True)
    tg_send(f"🎣 Orchestrator started — {len(ALL_ACCOUNTS)} worker(s)")

    # ---- pre-flight: bulk-refresh every account whose token is missing or
    # near expiry, in parallel. One accounts.json write at the end. ----
    bulk_refresh(ALL_ACCOUNTS, label_prefix="startup")

    # ---- backup proxy pool: every entry in BACKUP_PROXIES_FILE that isn't
    # already pinned to an account. ensure_working_proxy() drains this when a
    # worker's primary proxy goes dead. ----
    load_backup_pool(ALL_ACCOUNTS)

    # ---- pre-flight proxy check: probe every assigned + backup proxy and
    # abort if we can't cover the dead/missing assignments. Skipped entirely
    # when STRICT_PROXY_PREFLIGHT=False. ----
    if not preflight_proxies(ALL_ACCOUNTS):
        sys.exit(1)

    # ---- background sweeper: every REFRESH_SWEEP_INTERVAL seconds, refresh
    # any account inside the REFRESH_BUFFER window (in parallel). ----
    threading.Thread(target=refresher_loop, args=(ALL_ACCOUNTS,), daemon=True).start()

    # Only fish accounts whose tutorial has been completed. Newly-registered
    # accounts sit idle here until tutorial.py (or register.py) marks them done.
    READY = [a for a in ALL_ACCOUNTS if a.get("tutorial_completed")]
    SKIPPED = [a for a in ALL_ACCOUNTS if not a.get("tutorial_completed")]
    if SKIPPED:
        print(f">> skipping {len(SKIPPED)} account(s) pending tutorial: "
              f"{[a.get('label') for a in SKIPPED][:10]}"
              f"{'...' if len(SKIPPED) > 10 else ''}", flush=True)
    if not READY:
        print(">> no tutorial-completed accounts; run `python tutorial.py` first")
        sys.exit(0)

    shared_stats = {}
    workers = [FisherWorker(a, shared_stats) for a in READY]
    fleet_start = time.time()
    for w in workers:
        w.start()
        time.sleep(0.05)  # tiny stagger; tokens are already pre-warmed

    threading.Thread(target=aggregator, args=(shared_stats, fleet_start), daemon=True).start()

    # Daily farming limit: trips STOP_FARMING after FARMING_HOURS_PER_DAY hours;
    # every worker exits cleanly on its next loop check. No-op if set to 0.
    if FARMING_HOURS_PER_DAY > 0:
        threading.Thread(target=daily_limit_watcher, args=(fleet_start,), daemon=True).start()
        print(f">> daily farming limit: {FARMING_HOURS_PER_DAY}h", flush=True)

    try:
        while True: time.sleep(60)
    except KeyboardInterrupt:
        print("\n▶ orchestrator stopped by user", flush=True)
        total_c = sum(s["caught"]         for s in shared_stats.values())
        total_p = sum(s["pebbles_gained"] for s in shared_stats.values())
        tg_send(f"🛑 Orchestrator stopped — caught {total_c}, pebbles +{total_p}")
        time.sleep(1.5)  # let final tg call deliver
