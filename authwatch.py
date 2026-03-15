#!/usr/bin/env python3
"""
AuthWatch – SSH login analyzer + session auditor
"""

import argparse
import subprocess
import json
import re
import sys

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def parse_time_arg(time_str: str) -> str:
    units = {"w": "weeks", "d": "days", "h": "hours", "m": "minutes"}
    match = re.fullmatch(r"(\d+)([wdhm])", time_str)
    if not match:
        print(f"[AuthWatch] ERROR: Invalid time format '{time_str}'. Use e.g. 2w, 2d, 1h, 30m")
        sys.exit(1)
    value, unit = match.groups()
    return f"{value} {units[unit]} ago"


def run_journalctl(since: str):
    cmd = ["journalctl", "-o", "json", "--since", since, "SYSLOG_IDENTIFIER=sshd"]
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        print("[AuthWatch] ERROR: journalctl not found. Is this a systemd-based system?")
        sys.exit(1)
    for line in process.stdout:
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def extract_ip(message: str) -> str:
    match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", message)
    return match.group(1) if match else "unknown"


def extract_user(message: str) -> str:
    match = re.search(r"(?:for|user) (\S+)", message)
    return match.group(1) if match else "unknown"


# ──────────────────────────────────────────────
# SSH log commands
# ──────────────────────────────────────────────

def show_success(since_raw: str, since_human: str):
    print(f"[AuthWatch] Successful logins since: {since_human}\n")
    count = 0
    print(f"{'USER':<20} {'FROM IP':<18} {'MESSAGE'}")
    print("-" * 70)
    for event in run_journalctl(since_raw):
        msg = event.get("MESSAGE", "")
        if "Accepted password" in msg or "Accepted publickey" in msg:
            user = extract_user(msg)
            ip   = extract_ip(msg)
            print(f"{user:<20} {ip:<18} {msg}")
            count += 1
    print(f"\n[AuthWatch] Total successful logins: {count}")


def show_failed(since_raw: str, since_human: str):
    print(f"[AuthWatch] Failed logins since: {since_human}\n")
    failed_ips: dict = {}
    entries = []

    for event in run_journalctl(since_raw):
        msg = event.get("MESSAGE", "")
        if "Failed password" in msg or "Invalid user" in msg:
            ip   = extract_ip(msg)
            user = extract_user(msg)
            failed_ips[ip] = failed_ips.get(ip, 0) + 1
            entries.append((user, ip, msg))

    print(f"{'USER':<20} {'FROM IP':<18} {'MESSAGE'}")
    print("-" * 70)
    for user, ip, msg in entries:
        print(f"{user:<20} {ip:<18} {msg}")

    if failed_ips:
        print(f"\n{'─' * 40}")
        print("  Top attacking IPs:")
        print(f"{'─' * 40}")
        for ip, cnt in sorted(failed_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip:<18} {cnt} attempts")

    print(f"\n[AuthWatch] Total failed logins: {len(entries)}")


# ──────────────────────────────────────────────
# Scan command
# ──────────────────────────────────────────────

def cmd_scan(args):
    try:
        from modules.session_audit  import run_session_audit
        from modules.persistence    import run_persistence_audit
        from modules.html_report    import generate_html
    except ImportError as e:
        print(f"[AuthWatch] ERROR: Could not load module: {e}")
        sys.exit(1)

    session_data     = run_session_audit()
    persistence_data = run_persistence_audit()

    data = {**session_data, "persistence": persistence_data}

    if args.report:
        out = args.output or "authwatch_report.html"
        generate_html(data, output_path=out)


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def main():
    raw = sys.argv[1:]

    # ── scan subcommand ──
    if raw and raw[0] == "scan":
        parser = argparse.ArgumentParser(
            description="AuthWatch – SSH login analyzer & security auditor"
        )
        subparsers = parser.add_subparsers(dest="command")
        scan_p = subparsers.add_parser("scan", help="Full system session audit")
        scan_p.add_argument("--report", action="store_true", help="Generate an HTML report")
        scan_p.add_argument("--output", type=str, help="Output path for HTML report (default: authwatch_report.html)")
        scan_p.set_defaults(func=cmd_scan)
        args = parser.parse_args()
        args.func(args)
        return

    # ── python3 authwatch.py <time> ──
    if len(raw) == 1 and raw[0] not in ("-h", "--help"):
        show_success(parse_time_arg(raw[0]), raw[0])
        return

    # ── python3 authwatch.py <time> failed ──
    if len(raw) == 2 and raw[1] == "failed":
        show_failed(parse_time_arg(raw[0]), raw[0])
        return

    # ── help / fallback ──
    print("AuthWatch – SSH login analyzer & security auditor")
    print()
    print("Usage:")
    print("  python3 authwatch.py <time>              Successful logins")
    print("  python3 authwatch.py <time> failed       Failed login attempts")
    print("  python3 authwatch.py scan                Full session audit (terminal)")
    print("  python3 authwatch.py scan --report       Full audit + HTML report")
    print("  python3 authwatch.py scan --report --output /tmp/report.html")
    print()
    print("Time format: 30m  2h  1d  2w")


if __name__ == "__main__":
    main()
