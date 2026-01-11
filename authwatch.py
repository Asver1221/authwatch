#!/usr/bin/env python3

import argparse
import subprocess
import json


def run_journalctl(since: str):
    """
    Run journalctl and yield JSON events.
    """
    cmd = [
        "journalctl",
        "-o", "json",
        "--since", since,
        "_SYSTEMD_UNIT=ssh.service",
    ]

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    for line in process.stdout:
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def main():
    parser = argparse.ArgumentParser(
        description="AuthWatch – auth log analyzer (journalctl)"
    )
    parser.add_argument(
        "--since",
        default="1h",
        help="Time range for journalctl (e.g. 5m, 1h, today)",
    )

    args = parser.parse_args()

    print(f"[AuthWatch] Reading journalctl since: {args.since}")
    count = 0

    for event in run_journalctl(args.since):
        message = event.get("MESSAGE", "")
        if "Failed password" in message:
            print(message)
            count += 1

    print(f"\n[AuthWatch] Failed SSH logins: {count}")


if __name__ == "__main__":
    main()
