# AuthWatch

AuthWatch is a simple CLI tool for analyzing Linux authentication logs
using journalctl.

## Requirements

- Linux (tested on Ubuntu/Debian)
- Python 3.10+
- Access to system authentication logs

---

## Permissions (Important)

AuthWatch reads **security-related system logs**, which are protected by default
on Linux systems.

To run AuthWatch **without sudo**, the user must be a member of the following groups:

- `adm` – access to `/var/log/auth.log`
- `systemd-journal` – access to `journalctl` logs

### Add required groups

Run the following commands as root or with sudo:

```bash
sudo usermod -aG adm $USER
sudo usermod -aG systemd-journal $USER

## Usage
bash
python3 authwatch.py --since "1 hour ago"
