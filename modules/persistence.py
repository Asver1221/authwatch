#!/usr/bin/env python3
"""
persistence.py – Detects common attacker persistence mechanisms.

Checks:
  - Crontabs: system-wide and per-user
  - SSH authorized_keys for all users
  - /etc/passwd – new accounts, accounts with shell, UID 0 accounts
  - /etc/sudoers and /etc/sudoers.d – unexpected sudo rules
  - Systemd user units – backdoor services
  - Shell RC files – .bashrc, .bash_profile, .profile modifications
"""

import os
import re
from datetime import datetime
from pathlib import Path

from .utils import c, header, flag, run_cmd, read_file, file_age_days


# ──────────────────────────────────────────────
# System users
# ──────────────────────────────────────────────

def get_real_users() -> list[dict]:
    """Return users with home directories (likely real accounts, not system accounts)."""
    users = []
    passwd = read_file("/etc/passwd")
    if not passwd:
        return []
    for line in passwd.splitlines():
        parts = line.strip().split(":")
        if len(parts) < 7:
            continue
        username, _, uid, gid, _, home, shell = parts[:7]
        uid = int(uid) if uid.isdigit() else -1
        users.append({
            "username": username,
            "uid":      uid,
            "home":     home,
            "shell":    shell,
        })
    return users


# ──────────────────────────────────────────────
# /etc/passwd – suspicious accounts
# ──────────────────────────────────────────────

def check_passwd(findings: list, verbose: bool = True) -> list[dict]:
    header("👤  /etc/passwd – USER ACCOUNTS")
    users = get_real_users()
    if not users:
        flag("Could not read /etc/passwd", "warn")
        return []

    interactive_shells = {"/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash",
                          "/usr/bin/zsh", "/bin/fish", "/usr/bin/fish"}
    nologin_patterns   = {"nologin", "false", "sync", "halt", "shutdown"}

    suspicious = []
    uid0       = []
    with_shell  = []

    for u in users:
        if u["uid"] == 0 and u["username"] != "root":
            uid0.append(u)
            findings.append({"level": "critical", "module": "passwd",
                              "text": f"UID 0 account (root-level): {u['username']}"})
        shell_name = os.path.basename(u["shell"])
        if u["shell"] in interactive_shells and u["uid"] >= 1000:
            with_shell.append(u)
        if u["uid"] >= 1000 and shell_name not in nologin_patterns and u["uid"] != 65534:
            suspicious.append(u)

    print(f"  {c('dim', f'Total accounts: {len(users)}  |  Interactive (uid≥1000): {len(suspicious)}')}\n")

    if uid0:
        for u in uid0:
            flag(f"UID 0 non-root account: {u['username']} (shell: {u['shell']})", "critical")
    else:
        flag("No unexpected UID 0 accounts found", "ok")

    if suspicious and verbose:
        print(f"\n  {'USERNAME':<20} {'UID':<8} {'SHELL':<25} {'HOME'}")
        print(f"  {'─'*20} {'─'*8} {'─'*25} {'─'*30}")
        for u in suspicious:
            shell_col = c("yellow", f"{u['shell']:<25}") if u["shell"] in interactive_shells else f"{u['shell']:<25}"
            user_col = c("green", f"{u['username']:<20}")
            print(f"  {user_col} {u['uid']:<8} {shell_col} {u['home']}")

    return users


# ──────────────────────────────────────────────
# /etc/sudoers
# ──────────────────────────────────────────────

def check_sudoers(findings: list, verbose: bool = True) -> dict:
    header("🔑  SUDO RULES  (/etc/sudoers + sudoers.d)")

    sources = []
    for path in ["/etc/sudoers"]:
        if os.access(path, os.R_OK):
            sources.append(path)
    sudoers_d = Path("/etc/sudoers.d")
    if sudoers_d.exists():
        try:
            sources += [str(p) for p in sudoers_d.iterdir() if p.is_file() and os.access(str(p), os.R_OK)]
        except PermissionError:
            pass

    found_nopasswd = []
    found_all      = []

    for path in sources:
        content = read_file(path)
        if not content:
            continue
        for lineno, line in enumerate(content.splitlines(), 1):
            line_stripped = line.strip()
            if line_stripped.startswith("#") or not line_stripped:
                continue
            if "NOPASSWD" in line_stripped:
                found_nopasswd.append((path, lineno, line_stripped))
            if re.search(r"ALL\s*=\s*\(ALL", line_stripped):
                found_all.append((path, lineno, line_stripped))

    if not sources:
        print()
        flag("Could not read sudoers (permission denied – run with sudo)", "info")
        return {"nopasswd": [], "all_rules": []}

    if found_nopasswd:
        print(f"\n  {c('bold', 'NOPASSWD entries (no password required for sudo):')}")
        for path, lineno, line in found_nopasswd:
            age = file_age_days(path)
            age_str = f"{age:.0f}d ago" if age is not None else "unknown"
            flag(f"{os.path.basename(path)}:{lineno}  {line}  [{age_str}]", "warn")
            findings.append({"level": "warn", "module": "sudoers",
                              "text": f"NOPASSWD rule in {path}:{lineno}: {line}"})
    else:
        print()
        flag("No NOPASSWD rules found", "ok")

    if found_all and verbose:
        print(f"\n  {c('bold', 'ALL=(ALL) entries')}  {c('dim', '(password still required – shown for reference):')}")
        for path, lineno, line in found_all:
            flag(f"{os.path.basename(path)}:{lineno}  {line}", "info")

    return {
        "nopasswd":  [line for _, _, line in found_nopasswd],
        "all_rules": [line for _, _, line in found_all],
    }


# ──────────────────────────────────────────────
# Crontabs
# ──────────────────────────────────────────────

def check_crontabs(findings: list, verbose: bool = True) -> list:
    header("⏰  CRONTABS")

    cron_paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
    ]

    entries = []

    # System cron files
    for path_str in cron_paths:
        path = Path(path_str)
        if not path.exists():
            continue
        try:
            files = [path] if path.is_file() else list(path.iterdir())
        except PermissionError:
            continue
        for f in files:
            if not f.is_file():
                continue
            content = read_file(str(f))
            if not content:
                continue
            age = file_age_days(str(f))
            for lineno, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Only accept lines that look like actual cron schedule entries
                if not re.match(r'^(@\w+|\*|[\d\-\*,/]+)\s', line):
                    continue
                entries.append({
                    "source": str(f),
                    "line":   line,
                    "age":    age,
                    "recent": age is not None and age < 7,
                })

    # User crontabs via crontab -l
    users = get_real_users()
    for u in users:
        if u["uid"] < 1000 and u["username"] != "root":
            continue
        output = run_cmd(["crontab", "-l", "-u", u["username"]])
        if output:
            for line in output.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                entries.append({
                    "source": f"crontab -u {u['username']}",
                    "line":   line,
                    "age":    None,
                    "recent": False,
                })

    if not entries:
        flag("No crontab entries found", "ok")
        return

    print(f"  {c('dim', f'Found {len(entries)} cron entries:')}\n")

    suspicious_patterns = [
        r"(wget|curl)\s+http",
        r"/tmp/",
        r"/dev/shm",
        r"base64",
        r"\|.*bash",
        r"nc\s+-",
        r"python.*-c",
    ]

    for e in entries:
        is_suspicious = any(re.search(p, e["line"], re.IGNORECASE) for p in suspicious_patterns)
        is_recent     = e["recent"]

        if is_suspicious:
            flag(f"[SUSPICIOUS] {e['source']}: {e['line']}", "critical")
            findings.append({"level": "critical", "module": "crontab",
                              "text": f"Suspicious cron entry in {e['source']}: {e['line']}"})
        elif is_recent:
            flag(f"[RECENT <7d] {e['source']}: {e['line']}", "warn")
            findings.append({"level": "warn", "module": "crontab",
                              "text": f"Recently modified cron entry in {e['source']}: {e['line']}"})
        else:
            if verbose:
                print(f"  {c('dim', '·')}  {e['source']}: {c('dim', e['line'])}")

    flagged = any(
        any(re.search(p, e["line"], re.IGNORECASE) for p in suspicious_patterns) or e["recent"]
        for e in entries
    )
    if not flagged:
        flag("No suspicious cron entries found", "ok")


# ──────────────────────────────────────────────
# SSH authorized_keys
# ──────────────────────────────────────────────

def check_authorized_keys(findings: list, verbose: bool = True) -> dict:
    header("🗝️   SSH AUTHORIZED_KEYS")
    print()

    users = get_real_users()
    found_any = False
    ak_dict: dict = {}

    for u in users:
        ak_path = os.path.join(u["home"], ".ssh", "authorized_keys")
        if not os.path.exists(ak_path):
            continue

        content = read_file(ak_path)
        if not content:
            continue

        age  = file_age_days(ak_path)
        keys = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]

        if not keys:
            continue

        found_any = True
        ak_dict[u["username"]] = keys
        age_str   = f"{age:.0f}d ago" if age is not None else "unknown"
        is_recent = age is not None and age < 7

        level = "warn" if is_recent else "info"
        flag(f"{u['username']} – {len(keys)} key(s)  [modified: {age_str}]  {ak_path}", level)

        if is_recent:
            findings.append({"level": "warn", "module": "authorized_keys",
                              "text": f"authorized_keys modified recently ({age_str}): {ak_path}"})

        if verbose:
            for key in keys:
                parts   = key.split()
                comment = parts[2] if len(parts) >= 3 else c("dim", "(no comment)")
                keytype = parts[0] if parts else "unknown"
                print(f"    {c('dim', keytype):<30} {c('cyan', comment)}")

    if not found_any:
        flag("No authorized_keys files found", "ok")


# ──────────────────────────────────────────────
# Systemd user units
# ──────────────────────────────────────────────

def check_systemd_units(findings: list, verbose: bool = True) -> list:
    header("⚙️   SYSTEMD USER UNITS")

    search_paths = []
    users = get_real_users()
    for u in users:
        search_paths.append(Path(u["home"]) / ".config" / "systemd" / "user")

    search_paths.append(Path("/etc/systemd/system"))
    search_paths.append(Path("/usr/local/lib/systemd/system"))

    found = []

    for base in search_paths:
        try:
            if not base.exists():
                continue
            service_files = list(base.rglob("*.service"))
        except PermissionError:
            continue
        for f in service_files:
            content = read_file(str(f))
            if not content:
                continue
            age     = file_age_days(str(f))
            age_str = f"{age:.0f}d ago" if age is not None else "unknown"

            exec_lines = [l.strip() for l in content.splitlines()
                          if l.strip().startswith("ExecStart")]

            suspicious = any(
                re.search(r"(/tmp/|/dev/shm|wget|curl|bash -c|base64|nc )", l, re.IGNORECASE)
                for l in exec_lines
            )
            recent = age is not None and age < 7

            found.append({
                "path":       str(f),
                "exec":       exec_lines,
                "suspicious": suspicious,
                "recent":     recent,
                "age_str":    age_str,
            })

    if not found:
        flag("No user systemd units found", "ok")
        print()
        return []

    print()
    for unit in found:
        level = "critical" if unit["suspicious"] else ("warn" if unit["recent"] else "info")
        label = "[SUSPICIOUS]" if unit["suspicious"] else ("[RECENT]" if unit["recent"] else "")
        if verbose or unit["suspicious"] or unit["recent"]:
            flag(f"{label} {unit['path']}  [{unit['age_str']}]", level)
        if verbose:
            print()
            for line in unit["exec"]:
                print(f"    {c('dim', line)}")
            print()
        if unit["suspicious"]:
            findings.append({"level": "critical", "module": "systemd",
                              "text": f"Suspicious systemd unit: {unit['path']}"})
    # print()

    return [u["path"] for u in found]


# ──────────────────────────────────────────────
# Shell RC files
# ──────────────────────────────────────────────

def check_rc_files(findings: list, verbose: bool = True):
    header("🐚  SHELL RC FILES  (.bashrc / .profile / .bash_profile)")
    print()

    rc_names = [".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile"]
    suspicious_patterns = [
        (r"(wget|curl)\s+http",              "download from URL"),
        (r"base64\s+-d",                     "base64 decode"),
        (r"nc\s+-[el]",                      "netcat listener/connect"),
        (r"LD_PRELOAD\s*=",                  "LD_PRELOAD hijack"),
        (r"LD_LIBRARY_PATH\s*=.*(/tmp|shm)", "library path pointing to /tmp"),
        (r"python.*-c\s+['\"]",              "inline python execution"),
        (r"/tmp/.*\.(sh|py|pl|rb)",          "executing script from /tmp"),
        (r"alias\s+sudo\s*=",               "sudo alias override"),
        (r"alias\s+ls\s*=.*(/tmp|shm)",      "ls alias override"),
    ]

    users = get_real_users()
    found_any = False

    for u in users:
        for rc in rc_names:
            rc_path = os.path.join(u["home"], rc)
            if not os.path.exists(rc_path):
                continue
            content = read_file(rc_path)
            if not content:
                continue

            age     = file_age_days(rc_path)
            age_str = f"{age:.0f}d ago" if age is not None else "unknown"
            recent  = age is not None and age < 7

            hits = []
            for lineno, line in enumerate(content.splitlines(), 1):
                for pattern, desc in suspicious_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        hits.append((lineno, line.strip(), desc))

            if hits or recent:
                found_any = True
                level = "critical" if hits else "info"
                flag(f"{u['username']} – {rc_path}  [modified: {age_str}]", level)
                for lineno, line, desc in hits:
                    print(f"    {c('red', f'line {lineno}:')} {line}  {c('dim', f'({desc})')}")
                    findings.append({"level": "critical", "module": "rc_files",
                                     "text": f"Suspicious RC file entry ({desc}): {rc_path}:{lineno}: {line}"})

    if not found_any:
        flag("No suspicious RC file entries found", "ok")


# ──────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────

def show_summary(findings: list):
    header("📊  PERSISTENCE AUDIT SUMMARY")

    critical = [f for f in findings if f["level"] == "critical"]
    warnings = [f for f in findings if f["level"] == "warn"]

    if not findings:
        flag("No persistence indicators found", "ok")
        return

    if critical:
        print(f"  {c('bold', c('red', f'● CRITICAL  ({len(critical)})'))}\n")
        for f in critical:
            print(f"  {c('red', '🔴')}  {f['text']}")
            print()

    if warnings:
        print(f"  {c('bold', c('yellow', f'● WARNINGS  ({len(warnings)})'))}\n")
        for f in warnings:
            print(f"  {c('yellow', '🟠')}  {f['text']}")
            print()


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def run_persistence_audit(verbose: bool = True) -> dict:
    print(c("bold", c("cyan",   "╔══════════════════════════════════════════════╗")))
    print(c("bold", c("cyan",   "║       AUTHWATCH – PERSISTENCE AUDIT          ║")))
    print(c("bold", c("cyan",   "╚══════════════════════════════════════════════╝")))

    findings: list = []

    users         = check_passwd(findings, verbose)
    sudoers_data  = check_sudoers(findings, verbose)
    crontabs_data = check_crontabs(findings, verbose)
    ak_data       = check_authorized_keys(findings, verbose)
    systemd_data  = check_systemd_units(findings, verbose)
    check_rc_files(findings, verbose)
    show_summary(findings)

    return {
        "findings":         findings,
        "generated":        datetime.now().isoformat(),
        "_users":           users or [],
        "_sudoers":         sudoers_data or {},
        "_crontabs":        crontabs_data or [],
        "_authorized_keys": ak_data or {},
        "_systemd_units":   systemd_data or [],
    }


if __name__ == "__main__":
    run_persistence_audit(verbose=True)
