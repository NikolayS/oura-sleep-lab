#!/usr/bin/env python3
"""Small OAuth helper for Oura API V2.

This intentionally uses only the Python standard library: the OAuth dance is
simple, and avoiding dependencies keeps the first private analysis portable.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"
TOKEN_PATH = ROOT / "data" / "tokens" / "oura_token.json"
OAUTH_STATE_PATH = ROOT / "data" / "tokens" / "oura_oauth_state.json"
ISSUER_URL = "https://moi.ouraring.com/oauth/v2/ext/oauth-anonymous"
DISCOVERY_URL = f"{ISSUER_URL}/.well-known/openid-configuration"
FALLBACK_AUTHORIZE_URL = "https://cloud.ouraring.com/oauth/authorize"
FALLBACK_TOKEN_URL = "https://api.ouraring.com/oauth/token"
DEFAULT_SCOPES = (
    "extapi:daily extapi:heartrate extapi:spo2 extapi:workout "
    "extapi:tag extapi:session extapi:personal"
)


def load_env(path: Path = ENV_PATH) -> dict[str, str]:
    env: dict[str, str] = {}
    if path.exists():
        for raw_line in path.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip().strip("'\"")

    for key in (
        "OURA_CLIENT_ID",
        "OURA_CLIENT_SECRET",
        "OURA_REDIRECT_URI",
        "OURA_SCOPES",
        "OURA_AUTHORIZE_URL",
        "OURA_TOKEN_URL",
    ):
        if os.environ.get(key):
            env[key] = os.environ[key]

    env.setdefault("OURA_REDIRECT_URI", "http://localhost:8765/callback")
    env.setdefault("OURA_SCOPES", DEFAULT_SCOPES)
    return env


def require_env(env: dict[str, str]) -> None:
    missing = [key for key in ("OURA_CLIENT_ID", "OURA_CLIENT_SECRET") if not env.get(key)]
    if missing:
        joined = ", ".join(missing)
        raise SystemExit(f"Missing {joined}; copy .env.example to .env and fill it in.")


def oauth_config(env: dict[str, str]) -> dict[str, str]:
    if env.get("OURA_AUTHORIZE_URL") and env.get("OURA_TOKEN_URL"):
        return {
            "authorization_endpoint": env["OURA_AUTHORIZE_URL"],
            "token_endpoint": env["OURA_TOKEN_URL"],
        }

    try:
        with urllib.request.urlopen(DISCOVERY_URL, timeout=10) as response:
            data = json.loads(response.read().decode())
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return {
            "authorization_endpoint": env.get("OURA_AUTHORIZE_URL", FALLBACK_AUTHORIZE_URL),
            "token_endpoint": env.get("OURA_TOKEN_URL", FALLBACK_TOKEN_URL),
        }

    return {
        "authorization_endpoint": env.get(
            "OURA_AUTHORIZE_URL",
            data.get("authorization_endpoint", FALLBACK_AUTHORIZE_URL),
        ),
        "token_endpoint": env.get(
            "OURA_TOKEN_URL",
            data.get("token_endpoint", FALLBACK_TOKEN_URL),
        ),
    }


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def save_oauth_state(state: str, verifier: str) -> None:
    OAUTH_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    current: dict[str, Any] = {}
    if OAUTH_STATE_PATH.exists():
        current = json.loads(OAUTH_STATE_PATH.read_text())
    current[state] = {"code_verifier": verifier}
    OAUTH_STATE_PATH.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
    OAUTH_STATE_PATH.chmod(0o600)


def load_code_verifier(state: str | None) -> str | None:
    if not state or not OAUTH_STATE_PATH.exists():
        return None
    current = json.loads(OAUTH_STATE_PATH.read_text())
    entry = current.get(state)
    if not entry:
        return None
    return entry.get("code_verifier")


def build_authorize_url(env: dict[str, str], state: str, verifier: str) -> str:
    config = oauth_config(env)
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": env["OURA_CLIENT_ID"],
            "redirect_uri": env["OURA_REDIRECT_URI"],
            "scope": env["OURA_SCOPES"],
            "state": state,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
    )
    return f"{config['authorization_endpoint']}?{query}"


def post_token_request(env: dict[str, str], payload: dict[str, str]) -> dict[str, Any]:
    config = oauth_config(env)
    body = urllib.parse.urlencode(
        payload
        | {
            "client_id": env["OURA_CLIENT_ID"],
            "client_secret": env["OURA_CLIENT_SECRET"],
        }
    ).encode()
    request = urllib.request.Request(
        config["token_endpoint"],
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        body_text = error.read().decode(errors="replace")
        try:
            error_body = json.loads(body_text)
        except json.JSONDecodeError:
            error_body = {"error": body_text}
        error_name = error_body.get("error") or error_body.get("title") or "oauth_error"
        description = (
            error_body.get("error_description")
            or error_body.get("detail")
            or "No extra detail from Oura."
        )
        raise SystemExit(
            f"Oura token request failed: HTTP {error.code} {error_name}: {description}"
        ) from error


def exchange_code(env: dict[str, str], code: str, verifier: str | None = None) -> dict[str, Any]:
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": env["OURA_REDIRECT_URI"],
    }
    if verifier:
        payload["code_verifier"] = verifier
    return post_token_request(
        env,
        payload,
    )


def refresh_token(env: dict[str, str], refresh: str) -> dict[str, Any]:
    return post_token_request(
        env,
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh,
        },
    )


def save_token(token: dict[str, Any]) -> None:
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_PATH.write_text(json.dumps(token, indent=2, sort_keys=True) + "\n")
    TOKEN_PATH.chmod(0o600)


def parse_callback_url(callback_url: str) -> dict[str, str]:
    parsed = urllib.parse.urlparse(callback_url)
    params = urllib.parse.parse_qs(parsed.query)
    if params.get("error"):
        raise SystemExit(f"Oura returned error: {params['error'][0]}")
    if not params.get("code"):
        raise SystemExit("No code= parameter found in callback URL.")
    return {
        "code": params["code"][0],
        "state": params.get("state", [""])[0],
    }


def run_callback_server(env: dict[str, str], state: str) -> str:
    parsed = urllib.parse.urlparse(env["OURA_REDIRECT_URI"])
    host = parsed.hostname or "localhost"
    port = parsed.port or 8765
    expected_path = parsed.path or "/callback"
    result: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            request_url = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(request_url.query)
            if request_url.path != expected_path:
                self.send_response(404)
                self.end_headers()
                return
            if params.get("state", [""])[0] != state:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"State mismatch.")
                return
            if params.get("error"):
                result["error"] = params["error"][0]
            elif params.get("code"):
                result["code"] = params["code"][0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Oura authorization captured. You can close this tab.")

    server = HTTPServer((host, port), Handler)
    server.handle_request()
    if result.get("error"):
        raise SystemExit(f"Oura returned error: {result['error']}")
    if not result.get("code"):
        raise SystemExit("Callback received, but no authorization code was present.")
    return result["code"]


def command_url(args: argparse.Namespace) -> None:
    env = load_env()
    require_env(env)
    state = args.state or secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(64)
    save_oauth_state(state, verifier)
    print(build_authorize_url(env, state, verifier))
    print(f"\nstate={state}")


def command_listen(args: argparse.Namespace) -> None:
    env = load_env()
    require_env(env)
    state = args.state or secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(64)
    save_oauth_state(state, verifier)
    print(build_authorize_url(env, state, verifier))
    print("\nOpen that URL in a browser on this machine; waiting for callback...", flush=True)
    code = run_callback_server(env, state)
    token = exchange_code(env, code, verifier)
    save_token(token)
    print(f"Saved token to {TOKEN_PATH}")


def command_exchange(args: argparse.Namespace) -> None:
    env = load_env()
    require_env(env)
    if args.callback_url:
        callback = parse_callback_url(args.callback_url)
        code = callback["code"]
        verifier = load_code_verifier(callback["state"])
    else:
        code = args.code
        verifier = args.code_verifier
    token = exchange_code(env, code, verifier)
    save_token(token)
    print(f"Saved token to {TOKEN_PATH}")


def command_refresh(_: argparse.Namespace) -> None:
    env = load_env()
    require_env(env)
    if not TOKEN_PATH.exists():
        raise SystemExit(f"Missing token file: {TOKEN_PATH}")
    current = json.loads(TOKEN_PATH.read_text())
    token = refresh_token(env, current["refresh_token"])
    if "refresh_token" not in token:
        token["refresh_token"] = current["refresh_token"]
    save_token(token)
    print(f"Refreshed token at {TOKEN_PATH}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(required=True)

    url_parser = sub.add_parser("url", help="Print Oura authorization URL.")
    url_parser.add_argument("--state")
    url_parser.set_defaults(func=command_url)

    listen_parser = sub.add_parser("listen", help="Listen locally and save token.")
    listen_parser.add_argument("--state")
    listen_parser.set_defaults(func=command_listen)

    exchange_parser = sub.add_parser("exchange", help="Exchange auth code for token.")
    group = exchange_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--code")
    group.add_argument("--callback-url")
    exchange_parser.add_argument("--code-verifier")
    exchange_parser.set_defaults(func=command_exchange)

    refresh_parser = sub.add_parser("refresh", help="Refresh saved access token.")
    refresh_parser.set_defaults(func=command_refresh)

    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
