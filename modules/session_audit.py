#!/usr/bin/env python3
"""
session_audit.py – SSH and system session auditor.
Collects data from: last, lastb, lastlog, who, w
"""

import subprocess
import re
from datetime import datetime
from typing import Optional


COLORS = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "red":     "\033[91m",
    "yellow":  "\033[93m",
    "green":   "\033[92m",
    "cyan":    "\033[96m",
    "dim":     "\033[2m",
    "magenta": "\033[95m",
}

def c(color: str, text: str) -> str:
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"

def header(title: str):
    print(f"\n{c('bold', c('cyan', '━' * 60))}")
    print(f"  {c('bold', title)}")
    print(f"{c('bold', c('cyan', '━' * 60))}")


def run_cmd(cmd: list) -> Optional[str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout.strip() if result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


# ── last ──────────────────────────────────────

def parse_last(limit: int = 30) -> list:
    output = run_cmd(["last", "-n", str(limit), "-F", "-w"])
    if not output:
        return []

    entries = []
    for line in output.splitlines():
        if not line.strip() or line.startswith("wtmp"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue

        user = parts[0]
        tty  = parts[1]
        ip   = parts[2] if re.match(r"[\d\.:]", parts[2]) else "local"
        date_str = " ".join(parts[3:9])
        duration = parts[-1] if "(" in parts[-1] else "active"

        entries.append({
            "user": user, "tty": tty, "ip": ip,
            "date": date_str, "duration": duration.strip("()"),
        })
    return entries


def show_last(limit: int = 20) -> list:
    header("📋  LOGIN HISTORY  (last)")
    entries = parse_last(limit)
    if not entries:
        print(c("yellow", "  No data or insufficient permissions to read wtmp."))
        return []

    print(f"  {c('dim', f'Last {len(entries)} entries:')}\n")
    print(f"  {'USER':<12} {'TTY':<8} {'FROM IP':<20} {'DATE':<28} {'DURATION'}")
    print(f"  {'─'*12} {'─'*8} {'─'*20} {'─'*28} {'─'*10}")

    for e in entries:
        user_col = c("green", f"{e['user']:<12}") if e["user"] not in ("reboot","shutdown") else c("dim", f"{e['user']:<12}")
        ip_col   = c("yellow", f"{e['ip']:<20}") if re.match(r"\d+\.\d+", e["ip"]) else f"{e['ip']:<20}"
        dur_col  = c("red", e["duration"]) if e["duration"] == "active" else e["duration"]
        print(f"  {user_col} {e['tty']:<8} {ip_col} {e['date']:<28} {dur_col}")

    ext_logins = [e for e in entries if re.match(r"\d+\.\d+", e["ip"]) and e["user"] not in ("reboot","shutdown")]
    if not ext_logins:
        print(f"\n  {c('green', '✅  No external logins found.')}")

    return entries


# ── lastb ─────────────────────────────────────

def parse_lastb(limit: int = 30) -> list:
    output = run_cmd(["lastb", "-n", str(limit), "-F", "-w"])
    if not output:
        return []

    entries = []
    for line in output.splitlines():
        if not line.strip() or line.startswith("btmp"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue

        user = parts[0]
        tty  = parts[1]
        ip   = parts[2] if re.match(r"[\d\.:]", parts[2]) else "local"
        date_str = " ".join(parts[3:9])
        entries.append({"user": user, "tty": tty, "ip": ip, "date": date_str})
    return entries


def show_lastb(limit: int = 20) -> list:
    header("🚫  FAILED LOGINS  (lastb)")
    entries = parse_lastb(limit)
    if not entries:
        print(c("yellow", "  No data (root required or btmp is empty)."))
        return []

    ip_counts = {}
    for e in entries:
        ip_counts[e["ip"]] = ip_counts.get(e["ip"], 0) + 1

    print(f"  {c('dim', f'Last {len(entries)} failed attempts:')}\n")
    print(f"  {'USER':<16} {'TTY':<8} {'FROM IP':<20} {'DATE'}")
    print(f"  {'─'*16} {'─'*8} {'─'*20} {'─'*28}")

    for e in entries:
        attempts = ip_counts.get(e["ip"], 1)
        ip_col = c("red", f"{e['ip']:<20}") if attempts > 5 else c("yellow", f"{e['ip']:<20}")
        user_col = c("red", f"{e['user']:<16}")
        print(f"  {user_col} {e['tty']:<8} {ip_col} {e['date']}")

    if ip_counts:
        print(f"\n  {c('bold', 'Top attacking IPs:')}")
        for ip, cnt in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            bar = "█" * min(cnt, 30)
            color = "red" if cnt > 10 else "yellow"
            print(f"  {ip:<22} {c(color, bar)} {cnt}")

    brute_ips = [ip for ip, cnt in ip_counts.items() if cnt > 10]
    if not brute_ips:
        print(f"\n  {c('green', '✅  No brute-force patterns detected.')}")

    return entries


# ── lastlog ───────────────────────────────────

def parse_lastlog() -> list:
    output = run_cmd(["lastlog"])
    if not output:
        return []

    entries = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        user = parts[0]
        if "Never logged in" in line:
            entries.append({"user": user, "ip": "-", "date": "Never", "never": True})
        elif len(parts) >= 5:
            ip   = parts[2] if re.match(r"[\d\.\:]", parts[2]) else "local"
            date = " ".join(parts[3:])
            entries.append({"user": user, "ip": ip, "date": date, "never": False})
    return entries


def show_lastlog() -> list:
    header("👤  LAST LOGIN PER USER  (lastlog)")
    entries = parse_lastlog()
    if not entries:
        print(c("yellow", "  No data from lastlog."))
        return []

    logged_in = [e for e in entries if not e["never"]]
    never     = [e for e in entries if e["never"]]

    print(f"  {c('dim', f'Have logged in: {len(logged_in)}, never: {len(never)}')}\n")
    print(f"  {'USER':<20} {'FROM IP':<20} {'LAST LOGIN'}")
    print(f"  {'─'*20} {'─'*20} {'─'*30}")

    for e in sorted(logged_in, key=lambda x: x["date"], reverse=True):
        ip_col = c("yellow", f"{e['ip']:<20}") if re.match(r"\d+\.\d+", e["ip"]) else f"{e['ip']:<20}"
        user_col = c("green", f"{e['user']:<20}")
        print(f"  {user_col} {ip_col} {e['date']}")

    if never:
        names = ", ".join(e["user"] for e in never[:10])
        print(f"\n  {c('dim', f'Accounts that never logged in: {names}')}")

    ext_last = [e for e in logged_in if re.match(r"\d+\.\d+", e["ip"])]
    if not ext_last:
        print(f"\n  {c('green', '✅  No external IPs in login history.')}")

    return entries


# ── who / w ───────────────────────────────────

def parse_w() -> list:
    output = run_cmd(["w", "-h"])
    if not output:
        return []

    entries = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        entries.append({
            "user":    parts[0],
            "tty":     parts[1],
            "from_ip": parts[2],
            "login_at":parts[3],
            "idle":    parts[4],
            "command": " ".join(parts[7:]) if len(parts) > 7 else "-",
        })
    return entries


def show_active_sessions() -> list:
    header("🟢  ACTIVE SESSIONS  (w)")
    w_entries = parse_w()

    if not w_entries:
        print(c("green", "  No active sessions."))
        return []

    print(f"  {'USER':<12} {'TTY':<8} {'FROM':<20} {'LOGIN':<8} {'IDLE':<8} {'COMMAND'}")
    print(f"  {'─'*12} {'─'*8} {'─'*20} {'─'*8} {'─'*8} {'─'*20}")
    for e in w_entries:
        from_col = c("yellow", f"{e['from_ip']:<20}") if re.match(r"\d+\.\d+", e["from_ip"]) else f"{e['from_ip']:<20}"
        cmd_col  = c("magenta", e["command"][:40])
        user_col = c("green", f"{e['user']:<12}")
        print(f"  {user_col} {e['tty']:<8} {from_col} {e['login_at']:<8} {e['idle']:<8} {cmd_col}")

    ext_active = [e for e in w_entries if re.match(r"\d+\.\d+", e.get("from_ip", ""))]
    if not ext_active:
        print(f"\n  {c('green', '✅  No active sessions from external IPs.')}")

    return w_entries


# ── Anomaly detection ─────────────────────────

def detect_anomalies(last_entries: list, lastb_entries: list, active: list) -> list:
    anomalies = []

    ip_fails = {}
    for e in lastb_entries:
        ip_fails[e["ip"]] = ip_fails.get(e["ip"], 0) + 1

    for ip, cnt in ip_fails.items():
        if cnt > 10:
            anomalies.append(f"🔴  Brute-force detected: {cnt} failed attempts from {ip}")

    fail_ips = set(ip_fails.keys())
    for e in last_entries:
        if e["ip"] in fail_ips and re.match(r"\d+\.\d+", e["ip"]):
            anomalies.append(f"🟠  Successful login from IP with prior failed attempts: {e['ip']} (user: {e['user']})")

    for e in active:
        if re.match(r"\d+\.\d+", e.get("from_ip", "")):
            anomalies.append(f"🟡  Active session from external IP: {e['from_ip']} (user: {e['user']})")

    for e in last_entries:
        if e["user"] == "root" and re.match(r"\d+\.\d+", e["ip"]):
            anomalies.append(f"🔴  Direct root login via SSH from {e['ip']}")

    return anomalies


def show_anomalies(anomalies: list):
    header("⚠️   DETECTED ANOMALIES")
    if not anomalies:
        print()
        print(c("green", "  ✅  No suspicious patterns detected."))
        return
    for a in anomalies:
        print(f"  {a}")


# ── Main ──────────────────────────────────────

def run_session_audit() -> dict:
    print(c("bold", c("cyan", "\n╔══════════════════════════════════════════════╗")))
    print(c("bold", c("cyan",   "║         AUTHWATCH – SESSION AUDIT            ║")))
    print(c("bold", c("cyan",   "╚══════════════════════════════════════════════╝")))

    last_data    = show_last(30)
    lastb_data   = show_lastb(30)
    lastlog_data = show_lastlog()
    active_data  = show_active_sessions()

    anomalies = detect_anomalies(last_data, lastb_data, active_data)
    show_anomalies(anomalies)

    return {
        "last":      last_data,
        "lastb":     lastb_data,
        "lastlog":   lastlog_data,
        "active":    active_data,
        "anomalies": anomalies,
        "generated": datetime.now().isoformat(),
    }
