# AuthWatch 🔍

A lightweight SSH login analyzer and session auditor for Linux systems running systemd.

Reads directly from `journald`, `wtmp`, and `btmp` – no agents, no dependencies, no config files.

---

## Features

- **Failed login analysis** – parse `journald` SSH logs, group by IP, show top attackers
- **Successful login tracking** – filter `Accepted password` / `Accepted publickey` events
- **Full session audit** – `last`, `lastb`, `lastlog`, `w` in one command
- **Anomaly detection** – brute-force patterns, root SSH logins, successful logins after failures
- **HTML report** – dark-themed, auto-generated, includes charts

---

## Project Structure

```
authwatch/
├── authwatch.py          # CLI entrypoint
├── fake_ssh_logins.py    # Test data generator (dev/testing only)
├── README.md
└── modules/
    ├── __init__.py
    ├── session_audit.py  # Audit logic: last, lastb, lastlog, w + anomaly detection
    └── html_report.py    # HTML report generator
```

---

## Requirements

- Python 3.10+
- Linux with `systemd` (uses `journalctl`, `last`, `lastb`, `lastlog`, `w`)
- Root or sudo for `lastb` (reads `/var/log/btmp`)

No external Python packages required.

---

## Installation

```bash
git clone https://github.com/youruser/authwatch.git
cd authwatch
mkdir -p modules
# session_audit.py and html_report.py go into modules/
touch modules/__init__.py
```

---

## Usage

### SSH log analysis (journald)

```bash
# Successful logins in the last hour
python3 authwatch.py 1h

# Failed login attempts in the last 2 days
python3 authwatch.py failed 2d

# Supported time formats: 30m  2h  1d  2w
```

### Full session audit

```bash
# Terminal output only
python3 authwatch.py scan

# Terminal + HTML report (saved to authwatch_report.html)
python3 authwatch.py scan --report

# Custom output path
python3 authwatch.py scan --report --output /tmp/report.html
```

---

## HTML Report

The `--report` flag generates a self-contained HTML file with:

- Stat cards: successful logins, failed attempts, active sessions, anomaly count
- Detected anomalies with severity levels (🔴 critical / 🟠 warning / 🟡 info)
- Active session table with commands being run
- Bar chart of top attacking IPs
- Full login history and failed login tables

---

## Anomaly Detection

AuthWatch flags the following patterns automatically:

| Severity | Condition |
|----------|-----------|
| 🔴 Critical | Brute-force: more than 10 failed attempts from one IP |
| 🔴 Critical | Direct root login via SSH |
| 🟠 Warning  | Successful login from an IP that had prior failed attempts |
| 🟡 Info     | Active session from an external IP |

---

## Testing with Fake Logs

`fake_ssh_logins.py` injects fake SSH entries into `journald` via `syslog` for local testing.

```bash
# 10 random failed attempts (default)
python3 fake_ssh_logins.py

# 50 brute-force hits from one IP
python3 fake_ssh_logins.py --mode brute -n 50

# Simulate a breach: failures followed by a successful login
python3 fake_ssh_logins.py --mode mixed -n 10

# Root login attempts
python3 fake_ssh_logins.py --mode root -n 20

# Force specific IP and user
python3 fake_ssh_logins.py --ip 1.2.3.4 --user admin --mode brute -n 30
```

Available modes: `failed`, `brute`, `success`, `mixed`, `root`

After injecting, verify with:

```bash
python3 authwatch.py failed 5m
python3 authwatch.py scan --report
```

> **Note:** `fake_ssh_logins.py` is intended for development and testing only. Injected entries appear real to `journald` and will show up in all log analysis tools.

---

## Planned Modules

- `filesystem.py` – SUID binaries, recently modified files, suspicious `/tmp` content
- `network.py` – open ports, unknown listening processes (`ss -tulpn`)
- `persistence.py` – crontabs, `authorized_keys`, new accounts in `/etc/passwd`
- `integrity.py` – `debsums` / `rpm -Va`, `rkhunter` integration

---

## License

MIT
