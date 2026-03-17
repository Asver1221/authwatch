#!/usr/bin/env python3
"""
diff.py – Baseline comparison for AuthWatch.

Compares a current snapshot against the saved baseline and returns
a structured diff that can be printed to terminal and embedded in
the HTML report.

Diff categories:
  users           – accounts added / removed / shell changed
  authorized_keys – keys added / removed per user
  sudoers         – NOPASSWD rules added / removed
  crontabs        – entries added / removed
  systemd_units   – service files added / removed
  stats           – login count deltas
"""

from .utils import c, header, flag


# ──────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────

def _added_removed(baseline: list, current: list) -> tuple[list, list]:
    """Return (added, removed) by set difference."""
    b = set(baseline)
    cur = set(current)
    return sorted(cur - b), sorted(b - cur)


# ──────────────────────────────────────────────
# Per-section diff functions
# ──────────────────────────────────────────────

def _diff_users(b: dict, cur: dict) -> list[dict]:
    findings = []

    b_users   = {u["username"]: u for u in b.get("users", [])}
    cur_users = {u["username"]: u for u in cur.get("users", [])}

    for username in sorted(cur_users.keys() - b_users.keys()):
        u = cur_users[username]
        findings.append({
            "level":   "warn",
            "section": "users",
            "text":    f"New account added: {username}  (uid={u['uid']}  shell={u['shell']})",
        })

    for username in sorted(b_users.keys() - cur_users.keys()):
        u = b_users[username]
        findings.append({
            "level":   "info",
            "section": "users",
            "text":    f"Account removed: {username}  (uid={u['uid']})",
        })

    for username in sorted(b_users.keys() & cur_users.keys()):
        bu = b_users[username]
        cu = cur_users[username]
        if bu["shell"] != cu["shell"]:
            findings.append({
                "level":   "warn",
                "section": "users",
                "text":    f"Shell changed: {username}  {bu['shell']} → {cu['shell']}",
            })
        if bu["uid"] != cu["uid"]:
            findings.append({
                "level":   "critical",
                "section": "users",
                "text":    f"UID changed: {username}  {bu['uid']} → {cu['uid']}",
            })

    return findings


def _diff_authorized_keys(b: dict, cur: dict) -> list[dict]:
    findings = []

    b_ak   = b.get("authorized_keys", {})
    cur_ak = cur.get("authorized_keys", {})

    all_users = set(b_ak.keys()) | set(cur_ak.keys())

    for username in sorted(all_users):
        b_keys   = set(b_ak.get(username, []))
        cur_keys = set(cur_ak.get(username, []))

        for key_hash in sorted(cur_keys - b_keys):
            findings.append({
                "level":   "critical",
                "section": "authorized_keys",
                "text":    f"New SSH key added for {username}  (hash: {key_hash})",
            })

        for key_hash in sorted(b_keys - cur_keys):
            findings.append({
                "level":   "info",
                "section": "authorized_keys",
                "text":    f"SSH key removed for {username}  (hash: {key_hash})",
            })

    return findings


def _diff_sudoers(b: dict, cur: dict) -> list[dict]:
    findings = []

    b_sudo   = b.get("sudoers", {})
    cur_sudo = cur.get("sudoers", {})

    added, removed = _added_removed(
        b_sudo.get("nopasswd", []),
        cur_sudo.get("nopasswd", []),
    )
    for rule in added:
        findings.append({
            "level":   "critical",
            "section": "sudoers",
            "text":    f"New NOPASSWD rule: {rule}",
        })
    for rule in removed:
        findings.append({
            "level":   "info",
            "section": "sudoers",
            "text":    f"NOPASSWD rule removed: {rule}",
        })

    added, removed = _added_removed(
        b_sudo.get("all_rules", []),
        cur_sudo.get("all_rules", []),
    )
    for rule in added:
        findings.append({
            "level":   "warn",
            "section": "sudoers",
            "text":    f"New ALL=(ALL) rule: {rule}",
        })
    for rule in removed:
        findings.append({
            "level":   "info",
            "section": "sudoers",
            "text":    f"ALL=(ALL) rule removed: {rule}",
        })

    return findings


def _diff_crontabs(b: dict, cur: dict) -> list[dict]:
    findings = []

    b_entries   = b.get("crontabs", {}).get("entries", [])
    cur_entries = cur.get("crontabs", {}).get("entries", [])

    added, removed = _added_removed(b_entries, cur_entries)

    for entry in added:
        findings.append({
            "level":   "warn",
            "section": "crontabs",
            "text":    f"New cron entry: {entry}",
        })
    for entry in removed:
        findings.append({
            "level":   "info",
            "section": "crontabs",
            "text":    f"Cron entry removed: {entry}",
        })

    return findings


def _diff_systemd(b: dict, cur: dict) -> list[dict]:
    findings = []

    added, removed = _added_removed(
        b.get("systemd_units", []),
        cur.get("systemd_units", []),
    )

    for path in added:
        findings.append({
            "level":   "warn",
            "section": "systemd_units",
            "text":    f"New systemd unit: {path}",
        })
    for path in removed:
        findings.append({
            "level":   "info",
            "section": "systemd_units",
            "text":    f"Systemd unit removed: {path}",
        })

    return findings


def _diff_stats(b: dict, cur: dict) -> list[dict]:
    findings = []

    b_stats   = b.get("stats", {})
    cur_stats = cur.get("stats", {})

    b_failed   = b_stats.get("failed_logins", 0)
    cur_failed = cur_stats.get("failed_logins", 0)
    delta      = cur_failed - b_failed

    if delta > 50:
        findings.append({
            "level":   "warn",
            "section": "stats",
            "text":    f"Failed logins increased: {b_failed} → {cur_failed} (+{delta})",
        })
    elif delta < 0:
        findings.append({
            "level":   "info",
            "section": "stats",
            "text":    f"Failed logins decreased: {b_failed} → {cur_failed} ({delta})",
        })

    # New IPs in top attackers
    b_ips   = set(b_stats.get("top_ips", {}).keys())
    cur_ips = set(cur_stats.get("top_ips", {}).keys())
    for ip in sorted(cur_ips - b_ips):
        count = cur_stats["top_ips"][ip]
        findings.append({
            "level":   "warn",
            "section": "stats",
            "text":    f"New attacking IP: {ip}  ({count} attempts)",
        })

    return findings


# ──────────────────────────────────────────────
# Main diff entry point
# ──────────────────────────────────────────────

def compute_diff(baseline: dict, current: dict) -> dict:
    """
    Compare *current* snapshot against *baseline*.
    Returns a dict with all findings and metadata, ready for
    terminal output and HTML report embedding.
    """
    findings = (
        _diff_users(baseline, current)
        + _diff_authorized_keys(baseline, current)
        + _diff_sudoers(baseline, current)
        + _diff_crontabs(baseline, current)
        + _diff_systemd(baseline, current)
        + _diff_stats(baseline, current)
    )

    return {
        "baseline_created": baseline.get("created", "?"),
        "current_created":  current.get("created", "?"),
        "hostname":         current.get("hostname", "?"),
        "findings":         findings,
        "has_critical":     any(f["level"] == "critical" for f in findings),
        "has_warnings":     any(f["level"] == "warn"     for f in findings),
    }


# ──────────────────────────────────────────────
# Terminal output
# ──────────────────────────────────────────────

def show_diff(diff: dict) -> None:
    header("🔍  DIFF vs BASELINE")

    print(
        f"  {c('dim', 'Baseline: ' + diff['baseline_created'][:19])}"
        f"  {c('dim', '→')}"
        f"  {c('dim', 'Now: '     + diff['current_created'][:19])}"
    )
    print()

    findings = diff.get("findings", [])

    if not findings:
        print(c("green", "  ✅  No changes detected since baseline.\n"))
        return

    level_order = {"critical": 0, "warn": 1, "info": 2}
    for f in sorted(findings, key=lambda x: level_order.get(x["level"], 9)):
        level_map = {"critical": "critical", "warn": "warn", "info": "info"}
        flag(f["text"], level_map.get(f["level"], "info"))
