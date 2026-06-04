#!/usr/bin/env python3
"""
Automate Pudgy World account registration + email verification.

Pipeline:
  1) GET  /self-service/registration/api           -> registration flow id
  2) POST /self-service/registration?flow=<id>     -> creates account, returns verification flow id
  3) Poll notletters.com inbox for verification email, extract 6-digit code
  4) POST /self-service/verification?flow=<id>     -> account marked verified

Credentials file: registration_credentials.txt
  One account per line, format:   email:password
  Lines starting with '#' are ignored.

Usage:
  python register.py                  # register every account in the file that isn't done yet
  python register.py user@x.com:pw    # register one ad-hoc account
"""

import json
import random
import re
import sys
import time
from pathlib import Path

import requests

import jwtharvest
import tg
import tutorial as tutorial_mod

ORY_BASE       = "https://auth-ory.pudgyworld.com"
CREDENTIALS_FILE = "credentials.txt"
ACCOUNTS_FILE    = "accounts.json"
LABEL_PREFIX     = "auto_"
NOTLETTERS_URL = "https://api.notletters.com/v1/letters"
NOTLETTERS_KEY = "aFLTAQ7mRUwCv19FeZucX5f1vPCU418I"
CREDS_FILE     = "registration_credentials.txt"
PROXIES_FILE   = "proxies.txt"
STATE_FILE     = "registered_accounts.json"   # tracks which emails finished

# Inbox polling
INBOX_POLL_INTERVAL = 5      # seconds between polls
INBOX_POLL_TIMEOUT  = 120    # give up after this many seconds

# Delay between accounts to look natural. Pick a random value in [MIN, MAX] s.
DELAY_BETWEEN_MIN = 15
DELAY_BETWEEN_MAX = 45

# If True and there are fewer proxies than accounts, the run stops once
# proxies run out (strict 1:1). If False, accounts past the proxy list go
# without a proxy.
STRICT_ONE_PROXY_PER_ACCOUNT = True


# ===================== I/O =====================
def load_credentials(path: str = CREDS_FILE) -> list[tuple[str, str]]:
    out = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            print(f"!! skipping malformed line: {raw!r}")
            continue
        email, password = line.split(":", 1)
        out.append((email.strip(), password.strip()))
    return out


def load_proxies(path: str = PROXIES_FILE) -> list[str]:
    """
    Parse proxies.txt. Accepted formats per line:
      scheme://host:port:user:pass   (e.g. http://relay-eu.proxyshard.com:8080:user:pw)
      host:port:user:pass            (scheme defaults to http://)

    Returns a list of requests-style proxy URLs `scheme://user:pass@host:port`.
    """
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Default to http:// when no scheme is given (proxyshard etc. are HTTP).
        if "://" not in line:
            line = "http://" + line
        scheme, rest = line.split("://", 1)
        parts = rest.split(":")
        if len(parts) != 4:
            print(f"!! proxy must be [scheme://]host:port:user:pass, skipping: {raw!r}")
            continue
        host, port, user, pw = parts
        out.append(f"{scheme}://{user}:{pw}@{host}:{port}")
    return out


def mask_proxy(proxy_url: str) -> str:
    """Hide password for log lines."""
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", proxy_url)


def load_state() -> dict:
    p = Path(STATE_FILE)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError):
        return {}


def save_state(state: dict) -> None:
    Path(STATE_FILE).write_text(json.dumps(state, indent=2), encoding="utf-8")


# ===================== STEPS =====================
def init_registration_flow(s: requests.Session) -> str:
    """Step 1: GET the API registration flow, return its id."""
    r = s.get(f"{ORY_BASE}/self-service/registration/api",
              headers={"Accept": "application/json"}, timeout=15)
    r.raise_for_status()
    flow_id = r.json()["id"]
    print(f"  [1] registration flow_id={flow_id}")
    return flow_id


def submit_registration(s: requests.Session, flow_id: str,
                        email: str, password: str) -> tuple[str, str]:
    """Step 2: POST credentials. Returns (session_token, verification_flow_id)."""
    r = s.post(
        f"{ORY_BASE}/self-service/registration",
        params={"flow": flow_id},
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json={
            "traits.email":  email,
            "password":      password,
            "csrf_token":    "",
            "method":        "password",
        },
        timeout=20,
    )
    if not r.ok:
        # Surface Ory's UI messages for a clean error.
        try:
            data = r.json()
            msgs = []
            for n in data.get("ui", {}).get("nodes", []):
                for m in n.get("messages", []):
                    if m.get("type") == "error":
                        msgs.append(f"{n['attributes'].get('name')}: {m.get('text')}")
            for m in data.get("ui", {}).get("messages", []) or []:
                if m.get("type") == "error":
                    msgs.append(m.get("text"))
            raise RuntimeError(f"registration HTTP {r.status_code}: {'; '.join(msgs) or r.text[:300]}")
        except ValueError:
            raise RuntimeError(f"registration HTTP {r.status_code}: {r.text[:300]}")

    data = r.json()
    session_token = data.get("session_token", "")
    verify_flow_id = None
    for cw in data.get("continue_with", []) or []:
        if cw.get("action") == "show_verification_ui":
            verify_flow_id = cw["flow"]["id"]
            break
    if not verify_flow_id:
        raise RuntimeError("no verification flow id in registration response")
    print(f"  [2] account created, verify_flow_id={verify_flow_id}")
    return session_token, verify_flow_id


def fetch_verification_code(email: str, password: str) -> str:
    """Step 3: poll notletters until the Pudgy verification email arrives,
    return the 6-digit code from its body."""
    code_re = re.compile(r"<b>\s*(\d{6})\s*</b>")
    deadline = time.time() + INBOX_POLL_TIMEOUT
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            r = requests.post(
                NOTLETTERS_URL,
                headers={
                    "Content-Type":  "text/plain",
                    "Authorization": f"Bearer {NOTLETTERS_KEY}",
                },
                data=json.dumps({
                    "email":    email,
                    "password": password,
                    "filters":  {"search": "pudgy", "star": False},
                }),
                timeout=15,
            )
            r.raise_for_status()
            letters = r.json().get("data", {}).get("letters", []) or []
        except Exception as e:
            print(f"  [3] inbox poll #{attempt} failed: {e!r} — retrying")
            letters = []

        for letter in letters:
            html = (letter.get("letter") or {}).get("html") or ""
            m = code_re.search(html)
            if m:
                code = m.group(1)
                print(f"  [3] got verification code: {code} (poll #{attempt})")
                return code

        print(f"  [3] no code yet (poll #{attempt}); sleeping {INBOX_POLL_INTERVAL}s")
        time.sleep(INBOX_POLL_INTERVAL)

    raise TimeoutError(f"no verification email for {email} within {INBOX_POLL_TIMEOUT}s")


def submit_verification(s: requests.Session, flow_id: str, code: str) -> dict:
    """Step 4: POST the code to complete email verification."""
    r = s.post(
        f"{ORY_BASE}/self-service/verification",
        params={"flow": flow_id},
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json={"code": code, "csrf_token": "", "method": "code"},
        timeout=20,
    )
    if not r.ok:
        raise RuntimeError(f"verification HTTP {r.status_code}: {r.text[:300]}")
    print(f"  [4] verification OK")
    return r.json()


# ===================== ONBOARDING (label, accounts.json, credentials.txt) =====================
import threading
_onboard_lock = threading.Lock()


def _read_json(path: str, default):
    try:
        if not Path(path).exists():
            return default
        return json.loads(Path(path).read_text(encoding="utf-8")) or default
    except (json.JSONDecodeError, ValueError):
        return default


def _next_auto_label() -> str:
    """Find the highest existing 'auto_NNNN' label and return the next one."""
    accs = _read_json(ACCOUNTS_FILE, [])
    highest = 0
    for a in accs:
        m = re.match(rf"^{re.escape(LABEL_PREFIX)}(\d+)$", str(a.get("label", "")))
        if m:
            highest = max(highest, int(m.group(1)))
    return f"{LABEL_PREFIX}{highest + 1:04d}"


def _append_credentials_line(label: str, email: str, password: str) -> None:
    """Append `label:email:password` to credentials.txt if not already there."""
    p = Path(CREDENTIALS_FILE)
    existing = p.read_text(encoding="utf-8") if p.exists() else ""
    needle = f"{label}:{email}:"
    for line in existing.splitlines():
        if line.strip().startswith(needle):
            return  # already present
    with p.open("a", encoding="utf-8") as f:
        if existing and not existing.endswith("\n"):
            f.write("\n")
        f.write(f"{label}:{email}:{password}\n")


def _upsert_account(entry: dict) -> None:
    """Insert or update an account in accounts.json by label."""
    p = Path(ACCOUNTS_FILE)
    accs = _read_json(ACCOUNTS_FILE, [])
    for i, a in enumerate(accs):
        if a.get("label") == entry["label"]:
            accs[i] = {**a, **entry}
            break
    else:
        accs.append(entry)
    p.write_text(json.dumps(accs, indent=2), encoding="utf-8")


def onboard_after_registration(email: str, password: str, proxy_raw: str | None) -> dict:
    """
    Post-verification onboarding, all under one lock so concurrent registrations
    don't race on accounts.json / credentials.txt:
      1) allocate a fresh auto_NNNN label
      2) append to credentials.txt
      3) write a fresh accounts.json stub (tutorial_completed=False)
      4) jwtharvest.refresh_account(label) → real JWT
      5) tutorial_mod.run_tutorial(account, proxy_raw) → flip tutorial_completed
    Returns the final account dict.
    """
    with _onboard_lock:
        label = _next_auto_label()
        _append_credentials_line(label, email, password)
        _upsert_account({
            "label": label,
            "access_token": "",
            "refresh_token": "",
            "access_expires_at": 0,
            "tutorial_completed": False,
            "penguin_name": "",
            "proxy_raw": proxy_raw,
        })

    # JWT outside the lock — full HTTP roundtrip, slow.
    print(f"  [5] onboarding label={label}: harvesting JWT...")
    jwtharvest.refresh_account(label)

    # Reload the account fresh from disk and run the tutorial.
    accs = _read_json(ACCOUNTS_FILE, [])
    account = next(a for a in accs if a.get("label") == label)
    print(f"  [6] onboarding label={label}: running tutorial...")
    tutorial_mod.run_tutorial(account, proxy_url=proxy_raw)
    print(f"  [6] onboarding label={label}: tutorial done, account ready")
    return account


# ===================== ORCHESTRATION =====================
def register_one(email: str, password: str, proxy: str | None = None) -> dict:
    """Run the full 4-step pipeline for one account. Returns a state-dict
    with session_token, identity_id, verified=True.

    `proxy` (requests-style URL, e.g. http://user:pass@host:port) is used
    for the Ory traffic. The notletters inbox poll always goes direct."""
    print(f"\n>> registering {email}"
          + (f"   via {mask_proxy(proxy)}" if proxy else "   (no proxy)"))
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0"})
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
        # Quick sanity probe so we fail fast on dead proxies (saves the 120s
        # inbox-poll dance if Ory was never going to be reachable).
        try:
            s.get(f"{ORY_BASE}/health/ready", timeout=10)
        except requests.RequestException as e:
            raise RuntimeError(f"proxy unreachable: {e}")

    reg_flow = init_registration_flow(s)
    session_token, verify_flow = submit_registration(s, reg_flow, email, password)
    code = fetch_verification_code(email, password)
    submit_verification(s, verify_flow, code)

    # Telegram: first notification — registration + verification done.
    tg.send(f"✅ Registered & verified: {email}")

    # Post-verification: harvest JWT, append to credentials.txt, run tutorial.
    onboarded = onboard_after_registration(email, password, proxy_raw=proxy)

    return {
        "email":              email,
        "session_token":      session_token,
        "proxy":              mask_proxy(proxy) if proxy else None,
        "verified":           True,
        "registered_at":      int(time.time()),
        "label":              onboarded["label"],
        "penguin_name":       onboarded.get("penguin_name"),
        "tutorial_completed": onboarded.get("tutorial_completed", False),
    }


def onboard_from_registered_accounts():
    """
    Backfill mode: scan registered_accounts.json for already-verified emails
    that haven't been onboarded yet (no entry in credentials.txt), and run
    the onboard pipeline for each (label + JWT + tutorial).
    Uses the same proxy that registration used, if recorded.
    """
    state = _read_json("registered_accounts.json", {})
    if not state:
        print("!! registered_accounts.json is empty"); sys.exit(1)

    # Build set of emails already in credentials.txt so we don't onboard twice.
    creds_emails = set()
    p = Path(CREDENTIALS_FILE)
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 3:
                creds_emails.add(parts[1])

    # Filter: verified, not yet onboarded.
    pending = [
        rec for rec in state.values()
        if rec.get("verified") and rec.get("email") not in creds_emails
    ]
    print(f">> onboarding {len(pending)} verified account(s) from "
          f"registered_accounts.json")

    if not pending:
        print("== nothing to onboard"); sys.exit(0)

    # We need the password too — read it back from registration_credentials.txt
    # (registered_accounts.json intentionally doesn't store plaintext passwords).
    pw_map = dict(load_credentials())   # email -> password

    ok = fail = 0
    for rec in pending:
        email = rec["email"]
        password = pw_map.get(email)
        if not password:
            print(f"!! {email}: no password in {CREDS_FILE}, skipping")
            fail += 1
            continue
        proxy = rec.get("proxy_raw")
        try:
            print(f"\n>> onboarding {email}"
                  + (f"   via {mask_proxy(proxy)}" if proxy else ""))
            onboard_after_registration(email, password, proxy_raw=proxy)
            ok += 1
        except Exception as e:
            print(f"!! {email}: FAILED -- {e}")
            fail += 1

        delay = random.uniform(DELAY_BETWEEN_MIN, DELAY_BETWEEN_MAX)
        if rec is not pending[-1]:
            print(f".. sleeping {delay:.1f}s before next account")
            time.sleep(delay)

    print(f"\n== onboard backfill done: {ok} ok, {fail} failed")
    sys.exit(0 if fail == 0 else 1)


def main():
    args = sys.argv[1:]
    if args and args[0] == "--onboard":
        onboard_from_registered_accounts(); return
    if args:
        # One-off mode: register the explicit email:password pair(s) from argv.
        pairs = []
        for a in args:
            if ":" not in a:
                print(f"!! '{a}' must be email:password")
                sys.exit(64)
            e, p = a.split(":", 1)
            pairs.append((e.strip(), p.strip()))
    else:
        pairs = load_credentials()
        if not pairs:
            print(f"!! {CREDS_FILE} is empty")
            sys.exit(1)

    state    = load_state()
    proxies  = load_proxies()
    print(f"== loaded {len(pairs)} account(s), {len(proxies)} proxy(ies)")

    # Build the stable 1-proxy-per-account mapping. If we've already assigned
    # a proxy to this email on a previous run, reuse it (so retries look like
    # the same user). Otherwise pull the next unused proxy off the list.
    used_proxies = {s.get("proxy_raw") for s in state.values() if s.get("proxy_raw")}
    proxy_queue  = [p for p in proxies if p not in used_proxies]

    def assign_proxy(email):
        existing = state.get(email, {}).get("proxy_raw")
        if existing:
            return existing
        if proxy_queue:
            return proxy_queue.pop(0)
        return None

    ok = fail = skipped = 0
    pending = [(e, p) for e, p in pairs if not state.get(e, {}).get("verified")]
    print(f"== {len(pending)} account(s) to register, {len(pairs) - len(pending)} already done")

    for i, (email, password) in enumerate(pairs):
        if state.get(email, {}).get("verified"):
            print(f"\n.. {email}: already verified, skipping")
            skipped += 1
            continue

        proxy = assign_proxy(email)
        if proxy is None and STRICT_ONE_PROXY_PER_ACCOUNT and proxies:
            print(f"!! {email}: no proxy available (strict 1:1) — stopping")
            fail += 1
            break

        try:
            result = register_one(email, password, proxy=proxy)
            result["proxy_raw"] = proxy   # keep the real URL for stable rerun assignment
            state[email] = result
            save_state(state)
            ok += 1
        except Exception as e:
            print(f"!! {email}: FAILED -- {e}")
            state[email] = {
                **state.get(email, {}),
                "email": email, "error": str(e), "verified": False,
                "proxy_raw": proxy,
                "last_attempt_at": int(time.time()),
            }
            save_state(state)
            fail += 1

        # Natural-feel jitter between accounts (skip after the last one).
        more_remaining = any(not state.get(e, {}).get("verified") for e, _ in pairs[i+1:])
        if more_remaining:
            delay = random.uniform(DELAY_BETWEEN_MIN, DELAY_BETWEEN_MAX)
            print(f".. sleeping {delay:.1f}s before next account")
            time.sleep(delay)

    print(f"\n== done: {ok} registered, {fail} failed, {skipped} skipped")
    sys.exit(0 if fail == 0 else 1)


if __name__ == "__main__":
    main()
