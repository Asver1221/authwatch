#!/usr/bin/env python3

import argparse

def main():
    parser = argparse.ArgumentParser(
        description="AuthWatch – basic auth log analyzer (journalctl)"
    )
    parser.add_argument(
        "--since",
        help="Time range for journalctl (e.g. 1h, 30m, today)",
        default="1d"
    )

    args = parser.parse_args()
    print(f"[AuthWatch] Analyzing auth logs from last {args.since}")

if __name__ == "__main__":
    main()
