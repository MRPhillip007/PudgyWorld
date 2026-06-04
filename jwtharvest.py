#!/usr/bin/env python3
"""
Automates the Pudgy World OAuth login flow:
  1) GET  /self-service/login/browser?refresh=true   -> flow id + csrf_token
  2) POST /self-service/login?flow=<id>              -> establishes Ory session
  3) GET  /oauth2/auth?...                           -> returns HTML with ory_ac code
  4) GET  /api/auth/get-token?code=...               -> final app token
"""

import base64
import json
import re
import secrets
import sys
from pathlib import Path

import requests

ORY_BASE      = "https://auth-ory.pudgyworld.com"
APP_BASE      = "https://auth.pudgyworld.com"
CLIENT_ID     = "098775a4-000a-4382-a726-5df3204d5840"
REDIRECT      = "https://play.pudgyworld.com"
SCOPE         = "offline_access player"
CREDS_FILE    = "credentials.txt"
ACCOUNTS_FILE = "accounts.json"

# Library-mode verbosity. Set jwtharvest.VERBOSE = False from orchestrator
# to silence per-step prints when refreshing many accounts in parallel.
VERBOSE = True


class LoginError(Exception):
    """Login flow failed. `kind` is one of: invalid_credentials, rate_limited, csrf, other."""
    def __init__(self, kind: str, message: str, ory_id: int | None = None):
        super().__init__(message)
        self.kind = kind
        self.ory_id = ory_id


# Ory Kratos error IDs we care about. Full list:
# https://www.ory.sh/docs/kratos/concepts/ui-user-interface#ui-error-codes
_ORY_ERROR_KINDS = {
    4000006: "invalid_credentials",   # wrong identifier/password
    4000007: "invalid_credentials",   # account does not exist
    4000010: "rate_limited",          # too many requests
    4000001: "csrf",                  # csrf token mismatch
}


def _raise_ory_error(r, identifier: str) -> None:
    """Parse an Ory error response and raise a typed LoginError."""
    try:
        data = r.json()
    except ValueError:
        raise LoginError("other", f"HTTP {r.status_code}: {r.text[:300]}")

    # Collect all UI messages (top-level + per-node)
    messages = list(data.get("ui", {}).get("messages", []) or [])
    for node in data.get("ui", {}).get("nodes", []) or []:
        for m in node.get("messages", []) or []:
            messages.append(m)

    errors = [m for m in messages if m.get("type") == "error"]
    if not errors:
        raise LoginError("other", f"HTTP {r.status_code} with no UI error messages")

    first = errors[0]
    ory_id = first.get("id")
    text = first.get("text", "unknown error")
    kind = _ORY_ERROR_KINDS.get(ory_id, "other")

    if kind == "invalid_credentials":
        raise LoginError(kind, f"Invalid credentials for {identifier}", ory_id)
    if kind == "rate_limited":
        raise LoginError(kind, f"Rate limited by Ory: {text}", ory_id)
    if kind == "csrf":
        raise LoginError(kind, f"CSRF rejected: {text}", ory_id)
    raise LoginError("other", f"Ory error {ory_id}: {text}", ory_id)


def load_credentials_map(path: str = CREDS_FILE) -> dict[str, tuple[str, str]]:
    """
    Parse credentials.txt. Supported per-line formats (first non-empty,
    non-'#' line wins per label):
        label:email:password   (preferred; maps label -> creds)
        email:password         (legacy; stored under label '__default__')
    """
    out: dict[str, tuple[str, str]] = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 3:
            label, email, password = parts[0], parts[1], ":".join(parts[2:])
            out[label.strip()] = (email.strip(), password.strip())
        elif len(parts) == 2:
            out.setdefault("__default__", (parts[0].strip(), parts[1].strip()))
        else:
            raise ValueError(f"{path}: malformed line: {raw!r}")
    if not out:
        raise ValueError(f"{path}: no credentials found")
    return out


def get_credentials(label: str, path: str = CREDS_FILE) -> tuple[str, str]:
    creds = load_credentials_map(path)
    if label in creds:
        return creds[label]
    if "__default__" in creds and len(creds) == 1:
        return creds["__default__"]
    raise KeyError(f"No credentials for label {label!r} in {path}")


def _decode_jwt_exp(access_token: str) -> int:
    """Return the `exp` (unix seconds) from a JWT without verifying signature."""
    try:
        payload_b64 = access_token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
        return int(claims.get("exp", 0))
    except Exception:
        return 0


def _load_accounts(path: str = ACCOUNTS_FILE) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _save_accounts(accounts: list[dict], path: str = ACCOUNTS_FILE) -> None:
    Path(path).write_text(json.dumps(accounts, indent=2), encoding="utf-8")


def refresh_account_inplace(account: dict, creds_path: str = CREDS_FILE) -> dict:
    """
    Run the full Ory login flow for account['label'] and update the dict
    in-place with new access_token, refresh_token, access_expires_at.
    Performs NO file I/O — caller batches writes. Returns the same dict.
    """
    label = account["label"]
    email, password = get_credentials(label, creds_path)
    token = login(email, password)["token"]
    account["access_token"]      = token["access_token"]
    account["refresh_token"]     = token.get("refresh_token", account.get("refresh_token", ""))
    account["access_expires_at"] = _decode_jwt_exp(token["access_token"])
    return account


def refresh_account(
    label: str,
    accounts_path: str = ACCOUNTS_FILE,
    creds_path: str = CREDS_FILE,
) -> dict:
    """
    Run the full login flow for `label`, then update that account's entry
    in accounts.json with the new access_token, refresh_token, and
    access_expires_at (unix seconds). Returns the updated account dict.

    If `label` does not exist in accounts.json, a new entry is appended.
    """
    email, password = get_credentials(label, creds_path)
    token = login(email, password)["token"]

    access  = token["access_token"]
    refresh = token.get("refresh_token", "")
    exp     = _decode_jwt_exp(access)

    accounts = _load_accounts(accounts_path)
    entry = next((a for a in accounts if a.get("label") == label), None)
    if entry is None:
        entry = {"label": label}
        accounts.append(entry)
    entry["access_token"]       = access
    entry["refresh_token"]      = refresh
    entry["access_expires_at"]  = exp
    _save_accounts(accounts, accounts_path)
    if VERBOSE: print(f"[*] {label}: tokens written, expires at unix {exp}")
    return entry


def ensure_fresh_token(
    label: str,
    skew_seconds: int = 300,
    accounts_path: str = ACCOUNTS_FILE,
    creds_path: str = CREDS_FILE,
) -> str:
    """
    Return a valid access_token for `label`, refreshing via full re-login
    if the current one is missing, expired, or within `skew_seconds` of expiry.
    """
    import time
    accounts = _load_accounts(accounts_path)
    entry = next((a for a in accounts if a.get("label") == label), None)
    now = int(time.time())
    if (
        entry
        and entry.get("access_token")
        and int(entry.get("access_expires_at") or 0) - skew_seconds > now
    ):
        return entry["access_token"]
    return refresh_account(label, accounts_path, creds_path)["access_token"]


def login(identifier: str, password: str) -> dict:
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0"})

    # ---- 1) init login flow ----
    r = s.get(
        f"{ORY_BASE}/self-service/login/browser",
        params={"refresh": "true"},
        headers={"Accept": "application/json"},
    )
    r.raise_for_status()
    flow = r.json()
    flow_id = flow["id"]

    csrf_token = None
    for node in flow["ui"]["nodes"]:
        if node["attributes"].get("name") == "csrf_token":
            csrf_token = node["attributes"]["value"]
            break
    if not csrf_token:
        raise RuntimeError("csrf_token not found in flow response")

    if VERBOSE: print(f"[1] flow_id={flow_id}")

    # ---- 2) submit credentials ----
    if VERBOSE: print(f"[1.5] cookies before login: {list(s.cookies.keys())}")
    r = s.post(
        f"{ORY_BASE}/self-service/login",
        params={"flow": flow_id},
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": ORY_BASE,
            "Referer": f"{ORY_BASE}/self-service/login?flow={flow_id}",
        },
        json={
            "identifier":  identifier,
            "password":    password,
            "csrf_token":  csrf_token,
            "method":      "password",
        },
    )
    if not r.ok:
        _raise_ory_error(r, identifier)
    if VERBOSE: print(f"[2] logged in as {identifier}")

    # ---- 3) OAuth2 authorize -> redirect carries the ory_ac code ----
    state = secrets.token_urlsafe(12)
    r = s.get(
        f"{ORY_BASE}/oauth2/auth",
        params={
            "response_type": "code",
            "client_id":     CLIENT_ID,
            "redirect_uri":  REDIRECT,
            "scope":         SCOPE,
            "state":         state,
        },
        headers={"Accept": "text/html,application/xhtml+xml"},
        allow_redirects=True,
    )
    r.raise_for_status()

    # Code may appear either in the final URL query string (preferred)
    # or embedded in the HTML body as `code:"ory_ac_..."`.
    code = None
    for hist in [*r.history, r]:
        if "code=" in hist.url:
            m = re.search(r"[?&]code=(ory_ac_[^&]+)", hist.url)
            if m:
                code = m.group(1)
                break
    if not code:
        m = re.search(r'code:"(ory_ac_[^"]+)"', r.text)
        if m:
            code = m.group(1)
    if not code:
        raise RuntimeError("ory_ac code not found in /oauth2/auth response")

    if VERBOSE: print(f"[3] code={code[:24]}...")

    # ---- 4) exchange code for app token ----
    r = s.get(
        f"{APP_BASE}/api/auth/get-token",
        params={"code": code, "app": "pudgyworld", "redirect_uri": REDIRECT},
        headers={"Accept": "application/json"},
    )
    r.raise_for_status()
    token = r.json()
    if VERBOSE: print(f"[4] token response keys: {list(token.keys())}")
    return token


def _cli():
    """
    Usage:
        python jwtharvest.py <label>     # refresh one account, write accounts.json
        python jwtharvest.py --all       # refresh every label in credentials.txt
    """
    args = sys.argv[1:]
    if not args:
        print(_cli.__doc__)
        sys.exit(64)

    if args[0] == "--all":
        labels = list(load_credentials_map(CREDS_FILE).keys())
    else:
        labels = args

    rc = 0
    for label in labels:
        try:
            refresh_account(label)
        except LoginError as e:
            rc = max(rc, {"invalid_credentials": 2, "rate_limited": 3, "csrf": 4}.get(e.kind, 1))
            print(f"[FAIL:{label}] {e.kind}: {e}")
        except KeyError as e:
            rc = max(rc, 6); print(f"[FAIL:{label}] {e}")
        except requests.RequestException as e:
            rc = max(rc, 5); print(f"[FAIL:{label}] network: {e}")
    sys.exit(rc)


if __name__ == "__main__":
    _cli()