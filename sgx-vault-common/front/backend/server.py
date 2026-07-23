#!/usr/bin/env python3
"""
SGX Vault Web Backend — Flask HTTP server that bridges the browser UI
to the SGX enclave via the existing `app` CLI binary using pexpect.

Security: listens ONLY on 127.0.0.1.  Passwords travel from enclave →
backend → browser over localhost loopback and are never persisted.
"""

import json
import os
import re
import signal
import sys
import threading
import time
from pathlib import Path

import pexpect
from flask import Flask, jsonify, request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
APP_BINARY = os.path.join(os.path.dirname(__file__), "..", "..", "app")
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8848
PROMPT_TIMEOUT = 5  # seconds to wait for each expected prompt

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Global state — a single App process and a lock for thread safety
# ---------------------------------------------------------------------------
_child: pexpect.spawn | None = None
_child_lock = threading.Lock()
_vault_loaded = False  # tracks whether the vault has been created or loaded


# ---------------------------------------------------------------------------
# Process lifecycle helpers
# ---------------------------------------------------------------------------

def _start_app() -> pexpect.spawn:
    """Launch the SGX vault CLI app and wait for the main menu."""
    child = pexpect.spawn(
        APP_BINARY,
        encoding="utf-8",
        timeout=PROMPT_TIMEOUT,
        cwd=os.path.dirname(APP_BINARY),
    )
    # Wait for the enclave-load message and then the "Choice:" prompt
    child.expect("Choice:")
    return child


def _ensure_app() -> pexpect.spawn:
    """Return the global app process, (re)starting it if necessary."""
    global _child, _vault_loaded
    with _child_lock:
        if _child is None or not _child.isalive():
            _child = _start_app()
            _vault_loaded = False
        return _child


def _send_command(child: pexpect.spawn, choice: str) -> None:
    """Send a menu choice digit followed by Enter."""
    child.sendline(choice)


def _expect_ok(child: pexpect.spawn) -> dict:
    """
    After a command that prints a result line ending in 'OK.' or 'Error: ...',
    capture that line and return a JSON-serialisable dict.
    """
    idx = child.expect([
        r"OK\.",                                    # 0 – success
        r"Error: (.+)",                             # 1 – known error
        r"ECALL failed: (0x[0-9a-fA-F]+)",         # 2 – SGX error
        pexpect.TIMEOUT,                            # 3
    ])
    if idx == 0:
        # Consume the rest of the line, then wait for the next menu
        child.expect("Choice:")
        return {"ok": True}
    elif idx == 1:
        msg = child.match.group(1).strip()
        child.expect("Choice:")
        return {"ok": False, "error": msg}
    elif idx == 2:
        code = child.match.group(1).strip()
        child.expect("Choice:")
        return {"ok": False, "error": f"SGX ECALL failed: {code}"}
    else:
        return {"ok": False, "error": "Timeout waiting for response"}


def _read_until_choice(child: pexpect.spawn) -> str:
    """Read output until the next 'Choice:' prompt, return captured text."""
    child.expect("Choice:")
    return child.before or ""


# ---------------------------------------------------------------------------
# High-level vault operations (wrapping CLI menu choices)
# ---------------------------------------------------------------------------

def vault_create() -> dict:
    """Menu [1] Create vault."""
    child = _ensure_app()
    global _vault_loaded
    with _child_lock:
        _send_command(child, "1")
        result = _expect_ok(child)
        if result["ok"]:
            _vault_loaded = True
        return result


def vault_load() -> dict:
    """Menu [2] Load vault from sealed file."""
    child = _ensure_app()
    global _vault_loaded
    with _child_lock:
        _send_command(child, "2")
        result = _expect_ok(child)
        if result["ok"]:
            _vault_loaded = True
        return result


def vault_add(service: str, username: str, password: str) -> dict:
    """Menu [3] Add credential."""
    child = _ensure_app()
    global _vault_loaded
    with _child_lock:
        _send_command(child, "3")
        child.expect("Service name:")
        child.sendline(service)
        child.expect("Username:")
        child.sendline(username)
        child.expect("Password:")
        child.sendline(password)
        result = _expect_ok(child)
        if result["ok"]:
            _vault_loaded = True
        return result


def vault_get(service: str) -> dict:
    """Menu [4] Get credential.  Returns {ok, username, password}."""
    child = _ensure_app()
    with _child_lock:
        _send_command(child, "4")
        child.expect("Service name:")
        child.sendline(service)
        output = _read_until_choice(child)

        username = ""
        password = ""
        ok_found = False
        for line in output.splitlines():
            s = line.strip()
            if s.startswith("Username: "):
                username = s[len("Username: "):]
            elif s.startswith("Password: "):
                password = s[len("Password: "):]
            elif s == "OK.":
                ok_found = True

        if ok_found:
            return {"ok": True, "username": username, "password": password}
        for line in output.splitlines():
            if line.strip().startswith("Error:"):
                return {"ok": False, "error": line.strip()}
        return {"ok": False, "error": "Unknown error"}


def vault_update(service: str, username: str, password: str) -> dict:
    """Menu [5] Update credential."""
    child = _ensure_app()
    with _child_lock:
        _send_command(child, "5")
        child.expect("Service name:")
        child.sendline(service)
        child.expect("New username:")
        child.sendline(username)
        child.expect("New password:")
        child.sendline(password)
        return _expect_ok(child)


def vault_delete(service: str) -> dict:
    """Menu [6] Delete credential."""
    child = _ensure_app()
    with _child_lock:
        _send_command(child, "6")
        child.expect("Service name:")
        child.sendline(service)
        return _expect_ok(child)


def vault_list() -> dict:
    """Menu [7] List services.  Returns {ok, services: [...]}."""
    child = _ensure_app()
    with _child_lock:
        _send_command(child, "7")
        child.expect("Choice:")
        raw = child.before or ""
        lines = raw.strip().splitlines()
        # Skip the echoed "7", collect lines until "OK." or "Error:"
        services = []
        for line in lines[1:]:
            s = line.strip()
            if s == "OK.":
                return {"ok": True, "services": services}
            if s.startswith("Error:"):
                return {"ok": False, "error": s}
            if s:
                services.append(s)
        return {"ok": False, "error": "Unexpected list output"}


def vault_list_detail() -> dict:
    """List services with usernames (no passwords). Single lock acquisition."""
    child = _ensure_app()
    with _child_lock:
        # Step 1: list services
        _send_command(child, "7")
        output = _read_until_choice(child)
        lines = output.strip().splitlines()
        services = []
        for line in lines[1:]:  # skip echoed "7"
            s = line.strip()
            if s == "OK.":
                break
            if s.startswith("Error:"):
                return {"ok": False, "error": s}
            if s:
                services.append(s)

        # Step 2: get username for each service
        items = []
        for svc in services:
            _send_command(child, "4")
            child.expect("Service name:")
            child.sendline(svc)
            out2 = _read_until_choice(child)
            username = ""
            for line in out2.splitlines():
                s = line.strip()
                if s.startswith("Username: "):
                    username = s[len("Username: "):]
            items.append({"service": svc, "username": username})

    return {"ok": True, "items": items}


def vault_versions() -> dict:
    """Menu [8] Show format and state versions."""
    child = _ensure_app()
    with _child_lock:
        _send_command(child, "8")
        output = _read_until_choice(child)
        # Parse "Format version: X, State version: Y"
        m = re.search(r"Format version:\s*(\d+),\s*State version:\s*(\d+)", output)
        if m:
            return {
                "ok": True,
                "format_version": int(m.group(1)),
                "state_version": int(m.group(2)),
            }
        return {"ok": False, "error": "Could not parse version info"}


def vault_save() -> dict:
    """Menu [9] Save vault to sealed file."""
    child = _ensure_app()
    with _child_lock:
        _send_command(child, "9")
        output = _read_until_choice(child)
        if "Vault saved" in output:
            m = re.search(r"Vault saved to '(.+?)' \((\d+) bytes\)", output)
            if m:
                return {
                    "ok": True,
                    "file": m.group(1),
                    "bytes": int(m.group(2)),
                }
            return {"ok": True}
        # Try to detect error
        m = re.search(r"Error:\s*(.+)", output)
        if m:
            return {"ok": False, "error": m.group(1).strip()}
        return {"ok": False, "error": output.strip() or "Unknown error"}


def vault_status() -> dict:
    """Return whether the vault is loaded."""
    global _vault_loaded
    return {"ok": True, "loaded": _vault_loaded}


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/api/status")
def api_status():
    return jsonify(vault_status())


@app.route("/api/create", methods=["POST"])
def api_create():
    return jsonify(vault_create())


@app.route("/api/load", methods=["POST"])
def api_load():
    return jsonify(vault_load())


@app.route("/api/list")
def api_list():
    return jsonify(vault_list())


@app.route("/api/list-detail")
def api_list_detail():
    return jsonify(vault_list_detail())


@app.route("/api/get", methods=["POST"])
def api_get():
    data = request.get_json(silent=True) or {}
    service = data.get("service", "").strip()
    if not service:
        return jsonify({"ok": False, "error": "service is required"}), 400
    return jsonify(vault_get(service))


@app.route("/api/add", methods=["POST"])
def api_add():
    data = request.get_json(silent=True) or {}
    service = data.get("service", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not service:
        return jsonify({"ok": False, "error": "service is required"}), 400
    if not password:
        return jsonify({"ok": False, "error": "password is required"}), 400
    return jsonify(vault_add(service, username, password))


@app.route("/api/update", methods=["POST"])
def api_update():
    data = request.get_json(silent=True) or {}
    service = data.get("service", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not service:
        return jsonify({"ok": False, "error": "service is required"}), 400
    if not password:
        return jsonify({"ok": False, "error": "password is required"}), 400
    return jsonify(vault_update(service, username, password))


@app.route("/api/delete", methods=["POST"])
def api_delete():
    data = request.get_json(silent=True) or {}
    service = data.get("service", "").strip()
    if not service:
        return jsonify({"ok": False, "error": "service is required"}), 400
    return jsonify(vault_delete(service))


@app.route("/api/save", methods=["POST"])
def api_save():
    return jsonify(vault_save())


@app.route("/api/versions")
def api_versions():
    return jsonify(vault_versions())


# ---------------------------------------------------------------------------
# CORS — allow the frontend (file:// or any local origin) to call the API
# ---------------------------------------------------------------------------

@app.before_request
def handle_cors_preflight():
    """Explicitly handle OPTIONS preflight so the browser can do CORS from file://."""
    if request.method == 'OPTIONS':
        resp = app.make_default_options_response()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return resp

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


# ---------------------------------------------------------------------------
# Cleanup on exit
# ---------------------------------------------------------------------------

def _cleanup():
    global _child
    if _child and _child.isalive():
        _child.sendline("0")  # Exit the app cleanly
        try:
            _child.expect("Goodbye.", timeout=2)
        except pexpect.TIMEOUT:
            pass
        _child.terminate(force=True)


atexit_registered = False


def _register_cleanup():
    global atexit_registered
    if not atexit_registered:
        import atexit
        atexit.register(_cleanup)
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
        atexit_registered = True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    if not os.path.isfile(APP_BINARY):
        print(f"ERROR: SGX vault app not found at '{APP_BINARY}'.")
        print("Build it first:  cd .. && make")
        sys.exit(1)

    _register_cleanup()

    print(f"SGX Vault Web Backend")
    print(f"  App binary : {APP_BINARY}")
    print(f"  Listening  : http://{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"  Frontend   : open front/index.html in your browser")
    print()

    # Pre-start the app process so the first request is fast
    try:
        _ensure_app()
        print("Enclave loaded and ready.\n")
    except Exception as e:
        print(f"WARNING: Could not pre-start app: {e}")
        print("The app will be started on the first API request.\n")

    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False, threaded=True)


if __name__ == "__main__":
    main()
