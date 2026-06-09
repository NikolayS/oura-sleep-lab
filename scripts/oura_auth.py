#!/usr/bin/env python3
"""Small OAuth helper for Oura API V2.

This intentionally uses only the Python standard library: the OAuth dance is
simple, and avoiding dependencies keeps the first private analysis portable.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"
TOKEN_PATH = ROOT / "data" / "tokens" / "oura_token.json"
AUTHORIZE_URL = "https://cloud.ouraring.com/oauth/authorize"
TOKEN_URL = "https://api.ouraring.com/oauth/token"


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
    ):
        if os.environ.get(key):
            env[key] = os.environ[key]

    env.setdefault("OURA_REDIRECT_URI", "http://localhost:8765/callback")
    env.setdefault("OURA_SCOPES", "daily heartrate spo2 workout tag session personal")
    return env


def require_env(env: dict[str, str]) -> None:
    missing = [key for key in ("OURA_CLIENT_ID", "OURA_CLIENT_SECRET") if not env.get(key)]
    if missing:
        joined = ", ".join(missing)
        raise SystemExit(f"Missing {joined}; copy .env.example to .env and fill it in.")


def build_authorize_url(env: dict[str, str], state: str) -> str:
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": env["OURA_CLIENT_ID"],
            "redirect_uri": env["OURA_REDIRECT_URI"],
            "scope": env["OURA_SCOPES"],
            "state": state,
        }
    )
    return f"{AUTHORIZE_URL}?{query}"


def exchange_code(env: dict[str, str], code: str) -> dict[str, Any]:
    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": env["OURA_REDIRECT_URI"],
            "client_id": env["OURA_CLIENT_ID"],
            "client_secret": env["OURA_CLIENT_SECRET"],
        }
    ).encode()
    request = urllib.request.Request(
        TOKEN_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode())


def refresh_token(env: dict[str, str], refresh: str) -> dict[str, Any]:
    body = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": env["OURA_CLIENT_ID"],
            "client_secret": env["OURA_CLIENT_SECRET"],
        }
    ).encode()
    request = urllib.request.Request(
        TOKEN_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode())


def save_token(token: dict[str, Any]) -> None:
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_PATH.write_text(json.dumps(token, indent=2, sort_keys=True) + "\n")
    TOKEN_PATH.chmod(0o600)


def parse_code_from_url(callback_url: str) -> str:
    parsed = urllib.parse.urlparse(callback_url)
    params = urllib.parse.parse_qs(parsed.query)
    if params.get("error"):
        raise SystemExit(f"Oura returned error: {params['error'][0]}")
    if not params.get("code"):
        raise SystemExit("No code= parameter found in callback URL.")
    return params["code"][0]


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
    print(build_authorize_url(env, state))
    print(f"\nstate={state}")


def command_listen(args: argparse.Namespace) -> None:
    env = load_env()
    require_env(env)
    state = args.state or secrets.token_urlsafe(24)
    print(build_authorize_url(env, state))
    print("\nOpen that URL in a browser on this machine; waiting for callback...", flush=True)
    code = run_callback_server(env, state)
    token = exchange_code(env, code)
    save_token(token)
    print(f"Saved token to {TOKEN_PATH}")


def command_exchange(args: argparse.Namespace) -> None:
    env = load_env()
    require_env(env)
    code = args.code or parse_code_from_url(args.callback_url)
    token = exchange_code(env, code)
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
    exchange_parser.set_defaults(func=command_exchange)

    refresh_parser = sub.add_parser("refresh", help="Refresh saved access token.")
    refresh_parser.set_defaults(func=command_refresh)

    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
