#!/usr/bin/env python3
"""
fake_ssh_logins.py – Injects fake SSH log entries into journald via syslog.
Requires: systemd (syslog module – standard on all systemd systems)

Usage:
  python3 fake_ssh_logins.py                        # 10 random failed attempts
  python3 fake_ssh_logins.py -n 50                  # 50 failed attempts
  python3 fake_ssh_logins.py -n 5 -d 1              # 5 attempts, 1s delay between each
  python3 fake_ssh_logins.py --mode brute           # simulate brute-force from single IP
  python3 fake_ssh_logins.py --mode success         # inject successful login entries
  python3 fake_ssh_logins.py --mode mixed           # mix of failed + successful
  python3 fake_ssh_logins.py --mode root            # direct root login attempts
  python3 fake_ssh_logins.py --ip 1.2.3.4 --user admin  # force specific IP and user
"""

import argparse
import random
import syslog
import time


# ──────────────────────────────────────────────
# Test data pools
# ──────────────────────────────────────────────

FAKE_IPS = [
    "181.176.14.90",
    "158.220.104.210",
    "77.236.30.31",
    "45.33.32.156",
    "91.121.44.200",
    "218.92.0.185",
    "103.57.220.100",
    "192.168.1.666",   # impossible IP – easy to spot in logs
]

FAKE_USERS = [
    "admin", "claude", "pi", "test", "deploy",
    "backup", "guest", "user", "postgres", "oracle",
]

INVALID_USERS = [
    "hacker", "scanner", "bot", "clawd", "nobody",
    "ftp", "web", "minecraft", "jenkins", "vagrant",
]


# ──────────────────────────────────────────────
# Injection core
# ──────────────────────────────────────────────

def inject(message: str):
    """Inject a log entry via syslog with ident 'sshd' – exactly like real sshd."""
    syslog.openlog(ident="sshd", facility=syslog.LOG_AUTH)
    syslog.syslog(syslog.LOG_INFO, message)
    syslog.closelog()


# ──────────────────────────────────────────────
# Message generators
# ──────────────────────────────────────────────

def msg_failed(user: str, ip: str) -> str:
    port = random.randint(1024, 65535)
    return f"Failed password for {user} from {ip} port {port} ssh2"

def msg_invalid(user: str, ip: str) -> str:
    port = random.randint(1024, 65535)
    return f"Invalid user {user} from {ip} port {port}"

def msg_success_password(user: str, ip: str) -> str:
    port = random.randint(1024, 65535)
    return f"Accepted password for {user} from {ip} port {port} ssh2"

def msg_success_pubkey(user: str, ip: str) -> str:
    port = random.randint(1024, 65535)
    key = "SHA256:" + "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/", k=43))
    return f"Accepted publickey for {user} from {ip} port {port} ssh2: RSA {key}"

def msg_root_failed(ip: str) -> str:
    port = random.randint(1024, 65535)
    return f"Failed password for root from {ip} port {port} ssh2"

def msg_disconnect(ip: str) -> str:
    port = random.randint(1024, 65535)
    return f"Disconnected from invalid user from {ip} port {port} [preauth]"


# ──────────────────────────────────────────────
# Pollution modes
# ──────────────────────────────────────────────

def mode_failed(count: int, delay: float, ip: str = None, user: str = None):
    """Random failed password attempts from random IPs."""
    print(f"[fake_ssh] Mode: FAILED  – {count} failed login attempts\n")
    for i in range(1, count + 1):
        u = user or random.choice(FAKE_USERS + INVALID_USERS)
        h = ip   or random.choice(FAKE_IPS)
        # mix failed password and invalid user messages
        msg = msg_failed(u, h) if random.random() > 0.3 else msg_invalid(u, h)
        inject(msg)
        print(f"  [{i:>3}/{count}] {msg}")
        if delay:
            time.sleep(delay)


def mode_brute(count: int, delay: float, ip: str = None, user: str = None):
    """Simulate a brute-force attack from a single IP against a single user."""
    attacker_ip   = ip   or random.choice(FAKE_IPS)
    target_user   = user or random.choice(["root", "admin", "ubuntu"])
    print(f"[fake_ssh] Mode: BRUTE-FORCE  – {count} attempts from {attacker_ip} against '{target_user}'\n")
    for i in range(1, count + 1):
        msg = msg_failed(target_user, attacker_ip)
        inject(msg)
        print(f"  [{i:>3}/{count}] {msg}")
        if delay:
            time.sleep(delay)


def mode_success(count: int, delay: float, ip: str = None, user: str = None):
    """Inject successful login entries."""
    print(f"[fake_ssh] Mode: SUCCESS  – {count} successful logins\n")
    for i in range(1, count + 1):
        u = user or random.choice(FAKE_USERS)
        h = ip   or random.choice(FAKE_IPS)
        msg = msg_success_pubkey(u, h) if random.random() > 0.5 else msg_success_password(u, h)
        inject(msg)
        print(f"  [{i:>3}/{count}] {msg}")
        if delay:
            time.sleep(delay)


def mode_mixed(count: int, delay: float, ip: str = None, user: str = None):
    """Mix of failed attempts followed by a successful login – simulates a successful breach."""
    fail_count = max(1, count - 2)
    print(f"[fake_ssh] Mode: MIXED  – {fail_count} failures then 1 successful login\n")

    attacker_ip  = ip   or random.choice(FAKE_IPS)
    target_user  = user or random.choice(FAKE_USERS)

    for i in range(1, fail_count + 1):
        msg = msg_failed(target_user, attacker_ip)
        inject(msg)
        print(f"  [{i:>3}/{count}] FAIL    {msg}")
        if delay:
            time.sleep(delay)

    # successful login from the same IP – triggers anomaly detection
    msg = msg_success_password(target_user, attacker_ip)
    inject(msg)
    print(f"  [{count:>3}/{count}] SUCCESS {msg}")


def mode_root(count: int, delay: float, ip: str = None, user: str = None):
    """Direct root login attempts – high severity in authwatch."""
    print(f"[fake_ssh] Mode: ROOT  – {count} direct root login attempts\n")
    for i in range(1, count + 1):
        h = ip or random.choice(FAKE_IPS)
        msg = msg_root_failed(h)
        inject(msg)
        print(f"  [{i:>3}/{count}] {msg}")
        if delay:
            time.sleep(delay)


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

MODES = {
    "failed":  mode_failed,
    "brute":   mode_brute,
    "success": mode_success,
    "mixed":   mode_mixed,
    "root":    mode_root,
}

def main():
    parser = argparse.ArgumentParser(
        description="fake_ssh_logins.py – inject fake SSH entries into journald for testing authwatch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  failed   Random failed password / invalid user attempts (default)
  brute    Concentrated brute-force from a single IP
  success  Successful logins only
  mixed    Failed attempts followed by a successful login (triggers anomaly)
  root     Direct root SSH login attempts

Examples:
  python3 fake_ssh_logins.py                          # 10 random failed attempts
  python3 fake_ssh_logins.py -n 50 --mode brute       # 50 brute-force hits
  python3 fake_ssh_logins.py -n 5  --mode mixed       # breach simulation
  python3 fake_ssh_logins.py --mode root -n 20 -d 0.5
  python3 fake_ssh_logins.py --ip 1.2.3.4 --user admin --mode brute -n 30
        """
    )
    parser.add_argument("-n", "--count",  type=int,   default=10,      help="Number of entries to inject (default: 10)")
    parser.add_argument("-d", "--delay",  type=float, default=0.0,     help="Delay in seconds between entries (default: 0)")
    parser.add_argument("--mode",         type=str,   default="failed", choices=MODES.keys(), help="Pollution mode (default: failed)")
    parser.add_argument("--ip",           type=str,   default=None,    help="Force a specific source IP")
    parser.add_argument("--user",         type=str,   default=None,    help="Force a specific username")
    args = parser.parse_args()

    print(f"[fake_ssh] Injecting into journald  (ident=sshd, facility=AUTH)")
    print(f"[fake_ssh] Mode: {args.mode.upper()}  |  Count: {args.count}  |  Delay: {args.delay}s\n")

    MODES[args.mode](args.count, args.delay, args.ip, args.user)

    print(f"\n[fake_ssh] Done. Verify with authwatch:")
    print(f"  python3 authwatch.py failed 5m")
    print(f"  python3 authwatch.py 5m")
    print(f"  python3 authwatch.py scan --report")


if __name__ == "__main__":
    main()
