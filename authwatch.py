#!/usr/bin/env python3
"""
AuthWatch – SSH login analyzer + session auditor
"""

import argparse
import subprocess
import json
import re
import sys

from modules.session_audit import run_session_audit
from modules.persistence   import run_persistence_audit
from modules.html_report   import generate_html
from modules.storage       import build_snapshot, save_baseline, load_baseline, save_snapshot, baseline_info
from modules.diff          import compute_diff, show_diff
from modules.process       import run_process_audit

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
    verbose       = getattr(args, "full",           False)
    save_base     = getattr(args, "save_baseline",  False)
    run_diff      = getattr(args, "diff",           False)

    session_data     = run_session_audit()
    persistence_data = run_persistence_audit(verbose=verbose)
    process_findings: list = []
    process_data = run_process_audit(process_findings, verbose=verbose)

    persistence_data["findings"].extend(process_findings)
    persistence_data["_processes"] = process_data
    data     = {**session_data, "persistence": persistence_data}
    snapshot = build_snapshot(session_data, persistence_data)

    # ── baseline mode ──────────────────────────
    if save_base:
        save_baseline(snapshot)
        return

    # ── diff mode ──────────────────────────────
    diff_data = None
    if run_diff:
        baseline = load_baseline()
        if baseline is None:
            print("[AuthWatch] No baseline found. Run with --save-baseline first.")
        else:
            baseline_info()
            diff_data = compute_diff(baseline, snapshot)
            show_diff(diff_data)
            save_snapshot(snapshot)

    # ── report ─────────────────────────────────
    if args.report:
        out = args.output or "authwatch_report.html"
        generate_html(data, output_path=out, diff_data=diff_data)


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
        scan_p.add_argument("--output", type=str,            help="Output path for HTML report (default: authwatch_report.html)")
        scan_p.add_argument("--full",           action="store_true", help="Show full verbose output for all modules")
        scan_p.add_argument("--save-baseline",  action="store_true", help="Save current state as baseline for future diffs")
        scan_p.add_argument("--diff",           action="store_true", help="Compare current state against saved baseline")
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
    print("  python3 authwatch.py <time>                    Successful logins")
    print("  python3 authwatch.py <time> failed             Failed login attempts")
    print("  python3 authwatch.py scan                      Session + persistence audit (summary)")
    print("  python3 authwatch.py scan --full               Full verbose output for all modules")
    print("  python3 authwatch.py scan --report             Audit + HTML report")
    print("  python3 authwatch.py scan --output /tmp/r.html Custom report path")
    print("  python3 authwatch.py scan --save-baseline      Save current state as baseline")
    print("  python3 authwatch.py scan --diff               Compare against baseline")
    print("  python3 authwatch.py scan --diff --report      Diff + HTML report with changes")
    print()
    print("Time format: 30m  2h  1d  2w")


if __name__ == "__main__":
    main()
