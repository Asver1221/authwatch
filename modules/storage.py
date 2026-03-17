#!/usr/bin/env python3
"""
storage.py – Baseline and snapshot persistence for AuthWatch.

Handles reading and writing of:
  - /var/lib/authwatch/baseline.json   (reference state)
  - /var/lib/authwatch/history/*.json  (per-scan snapshots)
"""

import hashlib
import json
import os
import socket
from datetime import datetime
from pathlib import Path
from typing import Optional

from .utils import c


# ──────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────

AUTHWATCH_DIR  = Path("/var/lib/authwatch")
BASELINE_FILE  = AUTHWATCH_DIR / "baseline.json"
HISTORY_DIR    = AUTHWATCH_DIR / "history"


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _ensure_dirs() -> bool:
    """Create storage directories if they don't exist. Returns False on permission error."""
    try:
        AUTHWATCH_DIR.mkdir(parents=True, exist_ok=True)
        HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        return True
    except PermissionError:
        print(c("red", "  ✗  Cannot create /var/lib/authwatch – run with sudo."))
        return False


def _hash_string(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _hash_list(items: list) -> str:
    return _hash_string(json.dumps(items, sort_keys=True))


# ──────────────────────────────────────────────
# Snapshot builder
# Converts raw audit data into a clean, diffable structure.
# ──────────────────────────────────────────────

def build_snapshot(session_data: dict, persistence_data: dict) -> dict:
    """
    Distil raw audit module output into a compact, diffable snapshot.

    Called both when saving a baseline and when saving a history entry,
    so the structure is always identical and safe to compare.
    """
    last  = session_data.get("last",  [])
    lastb = session_data.get("lastb", [])

    # ── Users ──────────────────────────────────
    # Sourced from persistence findings rather than re-reading passwd here,
    # so we don't need an extra import. The full user list comes from the
    # persistence module's get_real_users() call stored in findings context.
    # We pull it from the raw persistence dict if available.
    users_raw = persistence_data.get("_users", [])
    users = [
        {
            "username": u["username"],
            "uid":      u["uid"],
            "shell":    u["shell"],
            "home":     u["home"],
        }
        for u in users_raw
    ]

    # ── Authorized keys ────────────────────────
    # Store SHA-256 prefix of each key, not the key itself.
    # Keyed by username so we can detect per-user changes.
    authorized_keys = persistence_data.get("_authorized_keys", {})
    ak_hashed = {
        username: [_hash_string(key) for key in keys]
        for username, keys in authorized_keys.items()
    }

    # ── Sudoers ────────────────────────────────
    sudoers = persistence_data.get("_sudoers", {})

    # ── Crontabs ──────────────────────────────
    crontabs_raw = persistence_data.get("_crontabs", [])
    crontabs = {
        "hash":    _hash_list(crontabs_raw),
        "entries": crontabs_raw,
    }

    # ── Systemd units ──────────────────────────
    systemd_units = persistence_data.get("_systemd_units", [])

    # ── Login stats ────────────────────────────
    ip_fails: dict = {}
    for e in lastb:
        ip_fails[e["ip"]] = ip_fails.get(e["ip"], 0) + 1

    stats = {
        "successful_logins": len([
            e for e in last
            if e.get("user") not in ("reboot", "shutdown", "")
        ]),
        "failed_logins": len(lastb),
        "top_ips": dict(
            sorted(ip_fails.items(), key=lambda x: x[1], reverse=True)[:10]
        ),
    }

    return {
        "created":        datetime.now().isoformat(),
        "hostname":       socket.gethostname(),
        "users":          users,
        "authorized_keys": ak_hashed,
        "sudoers":        sudoers,
        "crontabs":       crontabs,
        "systemd_units":  systemd_units,
        "stats":          stats,
    }


# ──────────────────────────────────────────────
# Baseline
# ──────────────────────────────────────────────

def save_baseline(snapshot: dict) -> bool:
    """Write *snapshot* as the new baseline. Returns True on success."""
    if not _ensure_dirs():
        return False
    try:
        BASELINE_FILE.write_text(json.dumps(snapshot, indent=2))
        print(c("green", f"  ✅  Baseline saved: {BASELINE_FILE}"))
        print(c("dim",   f"      Created: {snapshot['created']}"))
        return True
    except PermissionError:
        print(c("red", f"  ✗  Cannot write {BASELINE_FILE} – run with sudo."))
        return False


def load_baseline() -> Optional[dict]:
    """Load and return the baseline, or None if it doesn't exist."""
    if not BASELINE_FILE.exists():
        return None
    try:
        return json.loads(BASELINE_FILE.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(c("red", f"  ✗  Failed to read baseline: {e}"))
        return None


def baseline_info() -> None:
    """Print a one-liner about the current baseline status."""
    if not BASELINE_FILE.exists():
        print(c("yellow", "  ⚠  No baseline found. Run with --save-baseline first."))
        return
    b = load_baseline()
    if b:
        print(c("dim", f"  Baseline: {b.get('created', '?')[:19]}  host: {b.get('hostname', '?')}"))


# ──────────────────────────────────────────────
# History snapshots
# ──────────────────────────────────────────────

def save_snapshot(snapshot: dict) -> Optional[Path]:
    """
    Write *snapshot* to history/ with a timestamp filename.
    Returns the path written, or None on failure.
    """
    if not _ensure_dirs():
        return None
    ts   = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    path = HISTORY_DIR / f"{ts}.json"
    try:
        path.write_text(json.dumps(snapshot, indent=2))
        print(c("dim", f"  Snapshot saved: {path}"))
        return path
    except PermissionError:
        print(c("red", f"  ✗  Cannot write to {HISTORY_DIR} – run with sudo."))
        return None


def list_snapshots() -> list[Path]:
    """Return all history snapshots sorted oldest → newest."""
    if not HISTORY_DIR.exists():
        return []
    return sorted(HISTORY_DIR.glob("*.json"))


def load_snapshot(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(c("red", f"  ✗  Failed to read snapshot {path.name}: {e}"))
        return None
