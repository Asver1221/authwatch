#!/usr/bin/env python3
"""
utils.py – Shared utilities for AuthWatch modules.

Provides: terminal colours, formatted output helpers,
subprocess wrapper, and common file helpers.
"""

import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional


# ──────────────────────────────────────────────
# Terminal colours
# ──────────────────────────────────────────────

COLORS = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "dim":     "\033[2m",
    "red":     "\033[91m",
    "yellow":  "\033[93m",
    "green":   "\033[92m",
    "cyan":    "\033[96m",
    "magenta": "\033[95m",
}


def c(color: str, text: str) -> str:
    """Wrap *text* in the ANSI escape for *color*."""
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


# ──────────────────────────────────────────────
# Formatted output
# ──────────────────────────────────────────────

def header(title: str) -> None:
    """Print a cyan section divider with *title*."""
    print(f"\n{c('bold', c('cyan', '━' * 60))}")
    print(f"  {c('bold', title)}")
    print(f"{c('bold', c('cyan', '━' * 60))}")


def flag(text: str, level: str = "warn") -> None:
    """
    Print a single finding line with a severity icon.

    Levels: ``critical`` 🔴 · ``warn`` 🟠 · ``info`` 🟡 · ``ok`` ✅
    """
    icons  = {"critical": "🔴", "warn": "🟠", "info": "🟡", "ok": "✅"}
    colors = {"critical": "red", "warn": "yellow", "info": "cyan", "ok": "green"}
    print(f"  {icons.get(level, '·')}  {c(colors.get(level, 'reset'), text)}")


# ──────────────────────────────────────────────
# Process / file helpers
# ──────────────────────────────────────────────

def run_cmd(cmd: list) -> Optional[str]:
    """
    Run *cmd* and return stdout, or ``None`` on failure / timeout.

    Never raises – safe to call without try/except at the call site.
    """
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return None


def read_file(path: str) -> Optional[str]:
    """Return the full text of *path*, or ``None`` if unreadable."""
    try:
        return Path(path).read_text(errors="replace")
    except (OSError, PermissionError):
        return None


def file_age_days(path: str) -> Optional[float]:
    """Return how many days ago *path* was last modified, or ``None``."""
    try:
        mtime = os.path.getmtime(path)
        return (datetime.now().timestamp() - mtime) / 86400
    except OSError:
        return None
