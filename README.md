# AuthWatch 🔍

A lightweight SSH login analyzer and session auditor for Linux systems running systemd.

Reads directly from `journald`, `wtmp`, and `btmp` – no agents, no dependencies, no config files.

---

## Features

- **Failed login analysis** – parse `journald` SSH logs, group by IP, show top attackers
- **Successful login tracking** – filter `Accepted password` / `Accepted publickey` events
- **Full session audit** – `last`, `lastb`, `lastlog`, `w` in one command
- **Persistence audit** – detects backdoors, suspicious crons, unauthorized SSH keys, RC file tampering
- **Anomaly detection** – brute-force patterns, root SSH logins, successful logins after failures
- **Baseline diff** – save a known-good snapshot and compare future scans against it
- **HTML report** – dark-themed, auto-generated, includes charts and diff section

---

## Project Structure

```
authwatch/
├── authwatch.py          # CLI entrypoint
├── fake_ssh_logins.py    # Test data generator (dev/testing only)
├── README.md
└── modules/
    ├── __init__.py
    ├── utils.py          # Shared helpers (colours, output, file/process utils)
    ├── session_audit.py  # Audit logic: last, lastb, lastlog, w + anomaly detection
    ├── persistence.py    # Persistence audit: crons, authorized_keys, sudoers, RC files
    ├── storage.py        # Baseline and snapshot read/write (/var/lib/authwatch/)
    ├── diff.py           # Snapshot comparison engine
    └── html_report.py    # HTML report generator
```

---

## Requirements

- Python 3.10+
- Linux with `systemd` (uses `journalctl`, `last`, `lastb`, `lastlog`, `w`)
- Root or sudo recommended (required for `lastb`, `/etc/sudoers`, `/var/log/btmp`, writing baseline)

No external Python packages required.

---

## Installation

```bash
git clone https://github.com/youruser/authwatch.git
cd authwatch
```

---

## Usage

### SSH log analysis (journald)

```bash
# Successful logins in the last hour
python3 authwatch.py 1h

# Failed login attempts in the last 2 days
python3 authwatch.py 2d failed

# Supported time formats: 30m  2h  1d  2w
```

### Full session + persistence audit

```bash
# Summary mode – session audit + persistence findings only
python3 authwatch.py scan

# Full verbose mode – all details for every module
sudo python3 authwatch.py scan --full

# Audit + HTML report
sudo python3 authwatch.py scan --report

# Full verbose + HTML report
sudo python3 authwatch.py scan --full --report

# Custom output path
sudo python3 authwatch.py scan --full --report --output /tmp/report.html
```

### Baseline diff

```bash
# Save current state as baseline (run once on a clean system)
sudo python3 authwatch.py scan --save-baseline

# Compare current state against baseline
sudo python3 authwatch.py scan --diff

# Diff + HTML report with changes section
sudo python3 authwatch.py scan --diff --report
```

---

## Persistence Audit

`scan` automatically runs a persistence audit alongside the session audit. In default mode it shows only findings (critical and warnings). Use `--full` to see all details.

Checks performed:

| Module | What it looks for |
|--------|-------------------|
| `/etc/passwd` | UID 0 non-root accounts, interactive shells |
| `/etc/sudoers` | NOPASSWD rules, ALL=(ALL) entries |
| Crontabs | System-wide and per-user, flags suspicious patterns (`wget`, `curl`, `/tmp/`, `base64`) |
| SSH authorized_keys | Per-user keys, flags recently modified files |
| Systemd user units | Suspicious `ExecStart` commands (`/tmp/`, `wget`, `nc`) |
| Shell RC files | `LD_PRELOAD`, `base64 -d`, netcat, `alias sudo=`, scripts from `/tmp/` |

---

## Baseline Diff

AuthWatch can save a snapshot of the system state and highlight changes in future scans.
Snapshots are stored in `/var/lib/authwatch/`:

```
/var/lib/authwatch/
├── baseline.json          # reference state (--save-baseline)
└── history/
    └── 2026-03-17T09-15-00.json   # snapshot saved on each --diff run
```

What gets compared:

| Section | Detects |
|---------|---------|
| Users | New/removed accounts, shell or UID changes |
| authorized_keys | Keys added or removed per user |
| Sudoers | NOPASSWD rules added or removed |
| Crontabs | Entries added or removed |
| Systemd units | Service files added or removed |
| Stats | Failed login spikes, new attacking IPs |

When used with `--report`, a **Changes vs Baseline** section is added to the HTML report.

---

## HTML Report

The `--report` flag generates a self-contained HTML file with:

- Stat cards: successful logins, failed attempts, active sessions, anomaly count
- Changes vs Baseline section (only when `--diff` is used)
- Detected anomalies with severity levels (🔴 critical / 🟠 warning / 🟡 info)
- Persistence findings grouped by module
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
| 🔴 Critical | UID 0 non-root account in `/etc/passwd` |
| 🔴 Critical | Suspicious cron entry or RC file modification |
| 🟠 Warning  | Successful login from an IP that had prior failed attempts |
| 🟠 Warning  | NOPASSWD sudo rule detected |
| 🟠 Warning  | authorized_keys modified in the last 7 days |
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
python3 authwatch.py 5m failed
sudo python3 authwatch.py scan --full --report
```

> **Note:** `fake_ssh_logins.py` is intended for development and testing only. Injected entries appear real to `journald` and will show up in all log analysis tools.

---

## Planned Modules

- `filesystem.py` – SUID binaries, recently modified files, suspicious `/tmp` content
- `network.py` – open ports, unknown listening processes (`ss -tulpn`)
- `integrity.py` – `debsums` / `rpm -Va`, `rkhunter` integration

---

## License

MIT
