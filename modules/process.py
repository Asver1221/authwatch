#!/usr/bin/env python3
"""
process.py – Suspicious process detector for AuthWatch.

Checks:
  - Processes running from /tmp, /dev/shm, /var/tmp (classic malware locations)
  - Processes with deleted/missing binaries (/proc/PID/exe points to deleted file)
  - Processes listening on ports from non-standard binary paths
"""

import os
import re
from pathlib import Path
from datetime import datetime

from .utils import c, header, flag


# ──────────────────────────────────────────────
# /proc helpers
# ──────────────────────────────────────────────

def _get_all_pids() -> list[int]:
    """Return list of all numeric PIDs from /proc."""
    pids = []
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pids.append(int(entry))
    except PermissionError:
        pass
    return pids


def _resolve_exe(pid: int) -> str | None:
    """
    Resolve /proc/PID/exe symlink.
    Returns path string, with ' (deleted)' suffix if the binary is gone.
    Returns None if unreadable (e.g. kernel thread or permission denied).
    """
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except (OSError, PermissionError):
        return None


def _get_comm(pid: int) -> str:
    """Return process name from /proc/PID/comm, fallback to '?'."""
    try:
        return Path(f"/proc/{pid}/comm").read_text().strip()
    except OSError:
        return "?"


def _get_cmdline(pid: int) -> str:
    """Return command line from /proc/PID/cmdline (null-separated), truncated."""
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        return raw.replace(b"\x00", b" ").decode(errors="replace").strip()[:80]
    except OSError:
        return ""


def _get_uid(pid: int) -> int | None:
    """Return real UID of process owner from /proc/PID/status."""
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        for line in status.splitlines():
            if line.startswith("Uid:"):
                return int(line.split()[1])
    except OSError:
        pass
    return None


# ──────────────────────────────────────────────
# /proc/net/tcp parser – listening ports
# ──────────────────────────────────────────────

def _get_listening_inodes() -> dict[str, int]:
    """
    Parse /proc/net/tcp and /proc/net/tcp6 to find listening sockets.
    Returns dict: inode_str -> port (int), only for LISTEN state (0A).
    """
    inode_to_port: dict[str, int] = {}
    for fpath in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(fpath).read_text().splitlines()[1:]  # skip header
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            if parts[3] != "0A":          # 0A = TCP_LISTEN
                continue
            try:
                port = int(parts[1].split(":")[1], 16)
            except (IndexError, ValueError):
                continue
            inode_to_port[parts[9]] = port
    return inode_to_port


def _pid_listening_port(pid: int, inode_map: dict[str, int]) -> int | None:
    """
    Check if any fd in /proc/PID/fd points to a listening socket inode.
    Returns the port number, or None.
    """
    fd_dir = f"/proc/{pid}/fd"
    try:
        fds = os.listdir(fd_dir)
    except (OSError, PermissionError):
        return None

    for fd in fds:
        try:
            target = os.readlink(f"{fd_dir}/{fd}")
            m = re.match(r"socket:\[(\d+)\]", target)
            if m and m.group(1) in inode_map:
                return inode_map[m.group(1)]
        except OSError:
            continue
    return None


# ──────────────────────────────────────────────
# Classification
# ──────────────────────────────────────────────

_SUSPICIOUS_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/")
_SYSTEM_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/opt/", "/snap/")


def _classify_exe(exe: str) -> str:
    """
    Return severity level for a given exe path.
      'critical' – running from /tmp, /dev/shm etc., or binary deleted
      'warn'     – running from /home, /root, or other non-standard path
      'ok'       – system path (/usr, /bin, /sbin, /opt …)
    """
    if "(deleted)" in exe:
        return "critical"
    for d in _SUSPICIOUS_DIRS:
        if exe.startswith(d):
            return "critical"
    for p in _SYSTEM_PREFIXES:
        if exe.startswith(p):
            return "ok"
    return "warn"


# ──────────────────────────────────────────────
# Scan functions
# ──────────────────────────────────────────────

def _scan_suspicious_exes() -> list[dict]:
    """Walk all PIDs, classify exe path, return findings for non-ok processes."""
    results = []
    for pid in _get_all_pids():
        exe = _resolve_exe(pid)
        if exe is None:
            continue

        level = _classify_exe(exe)
        if level == "ok":
            continue

        results.append({
            "pid":     pid,
            "comm":    _get_comm(pid),
            "exe":     exe,
            "cmdline": _get_cmdline(pid),
            "uid":     _get_uid(pid),
            "level":   level,
            "port":    None,
        })
    return results


def _scan_listening_processes() -> list[dict]:
    """
    Find processes listening on TCP ports from non-system binary paths.
    A non-system binary that is listening on ANY port is escalated to critical.
    """
    inode_map = _get_listening_inodes()
    if not inode_map:
        return []

    results = []
    for pid in _get_all_pids():
        exe = _resolve_exe(pid)
        if exe is None:
            continue

        port = _pid_listening_port(pid, inode_map)
        if port is None:
            continue

        base_level = _classify_exe(exe)
        if base_level == "ok":
            continue

        # non-system binary listening on a port → always critical
        results.append({
            "pid":     pid,
            "comm":    _get_comm(pid),
            "exe":     exe,
            "cmdline": _get_cmdline(pid),
            "uid":     _get_uid(pid),
            "level":   "critical",
            "port":    port,
        })
    return results


# ──────────────────────────────────────────────
# Output helpers
# ──────────────────────────────────────────────

def _print_process_table(entries: list[dict]) -> None:
    print(f"  {'PID':<8} {'NAME':<16} {'PORT':<8} {'EXE'}")
    print(f"  {'─'*8} {'─'*16} {'─'*8} {'─'*50}")

    level_order = {"critical": 0, "warn": 1}
    for e in sorted(entries, key=lambda x: level_order.get(x["level"], 9)):
        color    = "red" if e["level"] == "critical" else "yellow"
        pid_col  = c(color, f"{e['pid']:<8}")
        name_col = c(color, f"{e['comm']:<16}")
        port_col = f"{e['port']:<8}" if e["port"] else f"{'—':<8}"

        exe_display = e["exe"]
        if len(exe_display) > 50:
            exe_display = "…" + exe_display[-49:]
        exe_col = c(color, exe_display)

        print(f"  {pid_col} {name_col} {port_col} {exe_col}")

        if e["cmdline"] and e["cmdline"] != e["comm"]:
            print(f"  {' '*8} {c('dim', e['cmdline'][:72])}")


# ──────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────

def run_process_audit(findings: list, verbose: bool = False) -> list[dict]:
    """
    Run all process checks. Appends to *findings* list (shared with other modules).
    Returns list of suspicious process dicts for snapshot/report use.
    """
    header("🔬  PROCESS AUDIT")
    print()

    exe_hits       = _scan_suspicious_exes()
    listening_hits = _scan_listening_processes()

    # Merge by PID – prefer listening entry when both exist (has port info)
    by_pid: dict[int, dict] = {e["pid"]: e for e in exe_hits}
    for e in listening_hits:
        existing = by_pid.get(e["pid"])
        if existing is None or e["port"] is not None:
            by_pid[e["pid"]] = e

    all_hits = list(by_pid.values())
    critical = [e for e in all_hits if e["level"] == "critical"]
    warnings = [e for e in all_hits if e["level"] == "warn"]

    if not all_hits:
        flag("No suspicious processes detected", "ok")
        print()
        return []

    if critical:
        print(f"  {c('bold', c('red', f'● CRITICAL  ({len(critical)} process(es))'))}\n")
        _print_process_table(critical)
        print()

    if warnings and verbose:
        print(f"  {c('bold', c('yellow', f'● WARNINGS  ({len(warnings)} process(es))'))}\n")
        _print_process_table(warnings)
        print()
    elif warnings and not verbose:
        print(f"  {c('yellow', f'🟠  {len(warnings)} warning(s) – run with --full to see details')}")
        print()

    # ── Populate shared findings list ──────────

    for e in critical:
        port_note = f"  [listening on :{e['port']}]" if e["port"] else ""
        findings.append({
            "level":  "critical",
            "module": "processes",
            "text":   f"Suspicious process: PID {e['pid']} ({e['comm']})  "
                      f"exe={e['exe']}{port_note}",
        })

    for e in warnings:
        port_note = f"  [listening on :{e['port']}]" if e["port"] else ""
        findings.append({
            "level":  "warn",
            "module": "processes",
            "text":   f"Unusual process location: PID {e['pid']} ({e['comm']})  "
                      f"exe={e['exe']}{port_note}",
        })

    return all_hits
