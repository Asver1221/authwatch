#!/usr/bin/env python3
"""
filesystem.py – Suspicious filesystem detector for AuthWatch.

Checks:
  - SUID/SGID binaries outside standard system paths
  - Executable files in world-writable directories (/tmp, /dev/shm, /var/tmp)
  - Recently modified files in sensitive directories (/etc, /bin, /sbin, /usr/bin)
"""

import os
import stat
from pathlib import Path

from .utils import c, header, flag, file_age_days


# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

_SYSTEM_PREFIXES = (
    "/usr/bin/", "/usr/sbin/", "/usr/lib/",
    "/bin/", "/sbin/", "/lib/", "/lib64/",
    "/usr/local/bin/", "/usr/local/sbin/",
    "/snap/",
)

_WRITABLE_DIRS = (
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    "/run/shm",
)

_SENSITIVE_DIRS = (
    "/etc",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
)

# Files modified within this many days are considered recent
_RECENT_DAYS = 7

# Skip these filenames in /etc to avoid noise (package manager churn etc.)
_ETC_SKIP_PATTERNS = {
    ".pwd.lock", "ld.so.cache", "mtab", "resolv.conf",
    "adjtime", "machine-id", "hostname",
}


# ──────────────────────────────────────────────
# SUID / SGID scan
# ──────────────────────────────────────────────

def _is_standard_suid(path: str) -> bool:
    """Return True if *path* starts with a known system prefix."""
    return any(path.startswith(p) for p in _SYSTEM_PREFIXES)


def _scan_suid(scan_roots: tuple = ("/usr", "/bin", "/sbin", "/opt", "/home", "/tmp")) -> list:
    """
    Use `find -perm /6000` to locate SUID/SGID binaries quickly.
    -xdev keeps it within each filesystem so it never crosses mount points.
    """
    import subprocess

    existing_roots = [r for r in scan_roots if os.path.exists(r)]
    if not existing_roots:
        return []

    try:
        result = subprocess.run(
            ["find"] + existing_roots + ["-xdev", "-perm", "/6000", "-type", "f", "-print0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        paths = [p for p in result.stdout.split(b"\x00") if p]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []

    results = []
    for raw in paths:
        try:
            path_str    = raw.decode(errors="replace")
            st          = os.stat(path_str)
            has_suid    = bool(st.st_mode & stat.S_ISUID)
            has_sgid    = bool(st.st_mode & stat.S_ISGID)
            bit_label   = "SUID+SGID" if (has_suid and has_sgid) else ("SUID" if has_suid else "SGID")
            is_standard = _is_standard_suid(path_str)
            results.append({
                "path":        path_str,
                "bit":         bit_label,
                "owner_uid":   st.st_uid,
                "level":       "ok" if is_standard else "critical",
                "is_standard": is_standard,
            })
        except (OSError, PermissionError):
            continue
    return results


# ──────────────────────────────────────────────
# Executables in world-writable dirs
# ──────────────────────────────────────────────

def _scan_writable_dirs() -> list:
    results = []
    script_extensions = {".sh", ".py", ".pl", ".rb", ".php", ".js", ".elf"}
    for dir_str in _WRITABLE_DIRS:
        dir_path = Path(dir_str)
        if not dir_path.exists():
            continue
        try:
            for entry in dir_path.rglob("*"):
                try:
                    if entry.is_symlink() or not entry.is_file():
                        continue
                    st        = entry.stat()
                    is_exec   = bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                    is_script = entry.suffix.lower() in script_extensions
                    if not (is_exec or is_script):
                        continue
                    age     = file_age_days(str(entry))
                    age_str = f"{age:.0f}d ago" if age is not None else "unknown"
                    results.append({
                        "path":    str(entry),
                        "age_str": age_str,
                        "age":     age,
                        "level":   "critical",
                    })
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            continue
    return results


# ──────────────────────────────────────────────
# Recently modified files in sensitive dirs
# ──────────────────────────────────────────────

def _scan_recently_modified() -> list:
    results = []
    for dir_str in _SENSITIVE_DIRS:
        dir_path = Path(dir_str)
        if not dir_path.exists():
            continue
        try:
            glob = dir_path.rglob("*") if dir_str != "/etc" else dir_path.glob("*")
            for entry in glob:
                try:
                    if entry.is_symlink() or not entry.is_file():
                        continue
                    if entry.name in _ETC_SKIP_PATTERNS:
                        continue
                    age = file_age_days(str(entry))
                    if age is None or age > _RECENT_DAYS:
                        continue
                    results.append({
                        "path":    str(entry),
                        "age":     age,
                        "age_str": f"{age:.1f}d ago",
                        "dir":     dir_str,
                    })
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            continue
    return sorted(results, key=lambda x: x["age"])


# ──────────────────────────────────────────────
# Output helpers
# ──────────────────────────────────────────────

def _print_suid_table(entries: list) -> None:
    print(f"  {'BIT':<12} {'OWNER UID':<12} {'PATH'}")
    print(f"  {'─'*10} {'─'*10} {'─'*55}")
    for e in entries:
        color    = "red" if e["level"] == "critical" else "dim"
        bit_col  = c(color, f"{e['bit']:<12}")
        path_col = c(color, e["path"])
        print(f"  {bit_col} {e['owner_uid']:<12} {path_col}")


def _print_file_table(entries: list) -> None:
    print(f"  {'AGE':<12} {'PATH'}")
    print(f"  {'─'*10} {'─'*55}")
    for e in entries:
        age_col  = c("yellow", f"{e['age_str']:<12}")
        path_col = c("yellow", e["path"])
        print(f"  {age_col} {path_col}")


# ──────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────

def run_filesystem_audit(findings: list, verbose: bool = False) -> list:
    """
    Run all filesystem checks. Appends to *findings* list (shared with other modules).
    Returns list of finding dicts for snapshot/report use.
    """
    header("📁  FILESYSTEM AUDIT")
    print()

    all_hits: list = []

    # ── 1. SUID / SGID ────────────────────────
    print(f"  {c('bold', 'SUID / SGID binaries')}")
    print()

    suid_hits    = _scan_suid()
    non_standard = [e for e in suid_hits if not e["is_standard"]]
    standard     = [e for e in suid_hits if e["is_standard"]]

    if non_standard:
        print(f"  {c('bold', c('red', f'● Non-standard ({len(non_standard)} found)'))}\n")
        _print_suid_table(non_standard)
        print()
        for e in non_standard:
            findings.append({
                "level":  "critical",
                "module": "filesystem",
                "text":   f"Non-standard {e['bit']} binary: {e['path']}",
            })
        all_hits.extend(non_standard)
    else:
        flag("No non-standard SUID/SGID binaries found", "ok")
        print()

    if verbose and standard:
        print(f"  {c('dim', f'Standard SUID/SGID binaries ({len(standard)} total – shown in verbose mode):')}")
        _print_suid_table(standard)
        print()

    # ── 2. Executables in world-writable dirs ─
    print(f"  {c('bold', 'Executables in world-writable directories')}")
    print()

    writable_hits = _scan_writable_dirs()

    if writable_hits:
        print(f"  {c('bold', c('red', f'● {len(writable_hits)} executable(s) found in /tmp or /dev/shm'))}\n")
        _print_file_table(writable_hits)
        print()
        for e in writable_hits:
            findings.append({
                "level":  "critical",
                "module": "filesystem",
                "text":   f"Executable in world-writable dir: {e['path']}  [{e['age_str']}]",
            })
        all_hits.extend(writable_hits)
    else:
        flag("No executables found in /tmp, /dev/shm, /var/tmp", "ok")
        print()

    # ── 3. Recently modified sensitive files ──
    print(f"  {c('bold', f'Files modified in the last {_RECENT_DAYS} days (sensitive dirs)')}")
    print()

    recent_hits = _scan_recently_modified()

    if recent_hits:
        print(f"  {c('bold', c('yellow', f'● {len(recent_hits)} recently modified file(s)'))}\n")
        _print_file_table(recent_hits)
        print()
        for e in recent_hits:
            findings.append({
                "level":  "warn",
                "module": "filesystem",
                "text":   f"Recently modified: {e['path']}  [{e['age_str']}]",
            })
        all_hits.extend(recent_hits)
    else:
        flag("No recently modified files found in sensitive directories", "ok")
        print()

    return all_hits
