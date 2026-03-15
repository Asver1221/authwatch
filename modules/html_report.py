#!/usr/bin/env python3
"""
html_report.py – HTML report generator for session_audit data.
"""

from datetime import datetime


def _severity_badge(text: str, level: str) -> str:
    colors = {
        "critical": ("#ff4444", "#2a0a0a"),
        "warning":  ("#ff9900", "#2a1a00"),
        "info":     ("#00ccff", "#002233"),
        "ok":       ("#00ff88", "#00220f"),
    }
    fg, bg = colors.get(level, ("#cccccc", "#1a1a1a"))
    return f'<span class="badge" style="background:{bg};color:{fg};border:1px solid {fg}">{text}</span>'


def _anomaly_level(text: str) -> str:
    if "🔴" in text: return "critical"
    if "🟠" in text: return "warning"
    if "🟡" in text: return "info"
    return "ok"


def generate_html(data: dict, output_path: str = "authwatch_report.html"):
    generated = data.get("generated", datetime.now().isoformat())
    last       = data.get("last", [])
    lastb      = data.get("lastb", [])
    lastlog    = data.get("lastlog", [])
    active     = data.get("active", [])
    anomalies  = data.get("anomalies", [])

    total_success = len([e for e in last if e.get("user") not in ("reboot","shutdown","")])
    total_failed  = len(lastb)
    total_active  = len(active)
    total_anomaly = len(anomalies)

    def rows_last():
        if not last: return "<tr><td colspan='5' class='empty'>No data</td></tr>"
        out = []
        for e in last:
            is_root = "root-row" if e["user"] == "root" else ""
            is_ext  = "ext-ip" if e["ip"] not in ("local","-","") and "." in e["ip"] else ""
            dur_cls = "active-session" if e["duration"] == "active" else ""
            out.append(f"""<tr class="{is_root}">
                <td>{e['user']}</td>
                <td>{e['tty']}</td>
                <td class="{is_ext}">{e['ip']}</td>
                <td>{e['date']}</td>
                <td class="{dur_cls}">{e['duration']}</td>
            </tr>""")
        return "\n".join(out)

    def rows_lastb():
        if not lastb: return "<tr><td colspan='4' class='empty'>No data (root required)</td></tr>"
        ip_counts = {}
        for e in lastb:
            ip_counts[e["ip"]] = ip_counts.get(e["ip"], 0) + 1
        out = []
        for e in lastb:
            cnt = ip_counts.get(e["ip"], 1)
            lvl = "critical-row" if cnt > 10 else "warn-row"
            out.append(f"""<tr class="{lvl}">
                <td>{e['user']}</td>
                <td>{e['tty']}</td>
                <td>{e['ip']} {_severity_badge(str(cnt)+" attempts","critical" if cnt>10 else "warning")}</td>
                <td>{e['date']}</td>
            </tr>""")
        return "\n".join(out)

    def rows_active():
        if not active: return "<tr><td colspan='6' class='empty'>No active sessions</td></tr>"
        out = []
        for e in active:
            is_ext = "ext-ip" if "." in e.get("from_ip","") else ""
            out.append(f"""<tr>
                <td>{e['user']}</td>
                <td>{e['tty']}</td>
                <td class="{is_ext}">{e['from_ip']}</td>
                <td>{e['login_at']}</td>
                <td>{e['idle']}</td>
                <td class="cmd-cell">{e['command'][:60]}</td>
            </tr>""")
        return "\n".join(out)

    def anomaly_cards():
        if not anomalies:
            return '<div class="anomaly-ok">✓ No suspicious patterns detected</div>'
        out = []
        for a in anomalies:
            lvl = _anomaly_level(a)
            out.append(f'<div class="anomaly-card {lvl}">{a}</div>')
        return "\n".join(out)

    def persistence_cards():
        persistence = data.get("persistence", {})
        findings = persistence.get("findings", []) if persistence else []
        if not findings:
            return '<div class="anomaly-ok">✓ No persistence indicators found</div>'
        level_map = {"critical": "critical", "warn": "warning", "info": "info"}
        icons     = {"critical": "🔴", "warn": "🟠", "info": "🟡"}
        out = []
        for f in findings:
            lvl  = level_map.get(f.get("level", "info"), "info")
            icon = icons.get(f.get("level", "info"), "🟡")
            mod  = f.get("module", "").upper()
            txt  = f.get("text", "")
            out.append(f'<div class="anomaly-card {lvl}"><span style="opacity:.5;font-size:11px;margin-right:8px">[{mod}]</span>{icon}  {txt}</div>')
        return "\n".join(out)

    ip_counts: dict = {}
    for e in lastb:
        ip_counts[e["ip"]] = ip_counts.get(e["ip"], 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    chart_labels = str([ip for ip, _ in top_ips])
    chart_values = str([cnt for _, cnt in top_ips])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AuthWatch Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&family=Bebas+Neue&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  :root {{
    --bg:        #080c10;
    --bg2:       #0d1117;
    --bg3:       #151c24;
    --border:    #1e2d3d;
    --accent:    #00d4ff;
    --accent2:   #ff6b35;
    --red:       #ff4444;
    --yellow:    #ffaa00;
    --green:     #00ff88;
    --text:      #c9d1d9;
    --text-dim:  #6e7681;
    --font-mono: 'JetBrains Mono', monospace;
    --font-ui:   'Syne', sans-serif;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-mono);
    font-size: 13px;
    line-height: 1.6;
    min-height: 100vh;
  }}

  body::before {{
    content: '';
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,212,255,0.015) 2px,
      rgba(0,212,255,0.015) 4px
    );
    pointer-events: none;
    z-index: 999;
  }}

  .site-header {{
    background: linear-gradient(135deg, #0a1628 0%, #0d1117 50%, #120a1e 100%);
    border-bottom: 1px solid var(--border);
    padding: 2rem 3rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: relative;
    overflow: hidden;
  }}

  .site-header::after {{
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
  }}

  .logo {{
    font-family: var(--font-ui);
    font-size: 1.8rem;
    font-weight: 800;
    letter-spacing: -0.02em;
  }}

  .logo span {{ color: var(--accent); }}

  .header-meta {{
    text-align: right;
    color: var(--text-dim);
    font-size: 11px;
  }}

  .header-meta .ts {{
    color: var(--accent);
    font-size: 12px;
  }}

  .container {{
    max-width: 1400px;
    margin: 0 auto;
    padding: 2rem 3rem;
  }}

  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 2.5rem;
  }}

  .stat-card {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5rem;
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s;
  }}

  .stat-card:hover {{ border-color: var(--accent); }}

  .stat-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
  }}

  .stat-card.success::before {{ background: var(--green); }}
  .stat-card.failed::before  {{ background: var(--red); }}
  .stat-card.active::before  {{ background: var(--accent); }}
  .stat-card.anomaly::before {{ background: var(--yellow); }}

  .stat-label {{
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text-dim);
    margin-bottom: 0.5rem;
  }}

  .stat-value {{
    font-family: 'Bebas Neue', sans-serif;
    font-size: 3.2rem;
    font-weight: 400;
    line-height: 1;
    letter-spacing: 0.04em;
  }}

  .stat-card.success .stat-value {{ color: var(--green); }}
  .stat-card.failed  .stat-value {{ color: var(--red); }}
  .stat-card.active  .stat-value {{ color: var(--accent); }}
  .stat-card.anomaly .stat-value {{ color: var(--yellow); }}

  .section {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 1.5rem;
    overflow: hidden;
  }}

  .section-header {{
    padding: 1rem 1.5rem;
    background: var(--bg3);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-family: var(--font-ui);
    font-weight: 700;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }}

  .section-icon {{ font-size: 1.1rem; }}

  .table-wrap {{ overflow-x: auto; }}

  table {{
    width: 100%;
    border-collapse: collapse;
  }}

  thead th {{
    padding: 0.6rem 1rem;
    text-align: left;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text-dim);
    border-bottom: 1px solid var(--border);
    background: rgba(255,255,255,0.02);
  }}

  tbody td {{
    padding: 0.55rem 1rem;
    border-bottom: 1px solid rgba(30,45,61,0.5);
    vertical-align: middle;
  }}

  tbody tr:hover {{ background: rgba(0,212,255,0.03); }}
  tbody tr:last-child td {{ border-bottom: none; }}

  .root-row {{ background: rgba(255,68,68,0.05) !important; }}
  .root-row:hover {{ background: rgba(255,68,68,0.08) !important; }}
  .critical-row {{ background: rgba(255,68,68,0.06) !important; }}
  .warn-row {{ background: rgba(255,170,0,0.04) !important; }}

  .ext-ip {{ color: var(--yellow); }}
  .active-session {{ color: var(--red); font-weight: bold; }}
  .cmd-cell {{ color: var(--accent); font-size: 11px; }}
  .empty {{ text-align: center; padding: 2rem; color: var(--text-dim); }}

  .badge {{
    display: inline-block;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: bold;
    margin-left: 6px;
    vertical-align: middle;
  }}

  .anomaly-grid {{
    padding: 1.25rem 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }}

  .anomaly-card {{
    padding: 0.75rem 1rem;
    border-radius: 6px;
    border-left: 3px solid;
    font-size: 13px;
  }}

  .anomaly-card.critical {{ background: rgba(255,68,68,0.08);  border-color: var(--red);   }}
  .anomaly-card.warning  {{ background: rgba(255,170,0,0.08); border-color: var(--yellow); }}
  .anomaly-card.info     {{ background: rgba(0,212,255,0.06); border-color: var(--accent); }}
  .anomaly-ok {{
    padding: 1.5rem;
    text-align: center;
    color: var(--green);
    font-size: 14px;
  }}

  .chart-wrap {{
    padding: 1.5rem;
    height: 280px;
    display: flex;
    align-items: center;
    justify-content: center;
  }}

  .chart-wrap.empty-chart {{
    color: var(--text-dim);
    font-size: 13px;
  }}

  .two-col {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
    margin-bottom: 1.5rem;
  }}

  .two-col .section {{ margin-bottom: 0; }}

  footer {{
    text-align: center;
    padding: 2rem;
    color: var(--text-dim);
    font-size: 11px;
    border-top: 1px solid var(--border);
    margin-top: 2rem;
  }}

  @media (max-width: 900px) {{
    .stats-grid {{ grid-template-columns: 1fr 1fr; }}
    .two-col {{ grid-template-columns: 1fr; }}
    .container {{ padding: 1rem; }}
  }}
</style>
</head>
<body>

<header class="site-header">
  <div>
    <div class="logo">Auth<span>Watch</span></div>
    <div style="color:var(--text-dim);font-size:11px;margin-top:4px">SSH Session Audit Report</div>
  </div>
  <div class="header-meta">
    <div class="ts">{generated.replace("T", "  ")[:19]}</div>
    <div style="margin-top:4px">Generated automatically</div>
  </div>
</header>

<div class="container">

  <div class="stats-grid">
    <div class="stat-card success">
      <div class="stat-label">Successful Logins</div>
      <div class="stat-value">{total_success}</div>
    </div>
    <div class="stat-card failed">
      <div class="stat-label">Failed Attempts</div>
      <div class="stat-value">{total_failed}</div>
    </div>
    <div class="stat-card active">
      <div class="stat-label">Active Sessions</div>
      <div class="stat-value">{total_active}</div>
    </div>
    <div class="stat-card anomaly">
      <div class="stat-label">Anomalies</div>
      <div class="stat-value">{total_anomaly}</div>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <span class="section-icon">⚠️</span> Detected Anomalies
    </div>
    <div class="anomaly-grid">
      {anomaly_cards()}
    </div>
  </div>

  <div class="two-col">
    <div class="section">
      <div class="section-header">
        <span class="section-icon">🟢</span> Active Sessions (w)
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th>User</th><th>TTY</th><th>From</th>
            <th>Login</th><th>Idle</th><th>Command</th>
          </tr></thead>
          <tbody>{rows_active()}</tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <div class="section-header">
        <span class="section-icon">📊</span> Top Attacking IPs
      </div>
      {'<div class="chart-wrap"><canvas id="ipChart"></canvas></div>' if top_ips else '<div class="chart-wrap empty-chart">No failed login data available</div>'}
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <span class="section-icon">📋</span> Login History (last)
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>User</th><th>TTY</th><th>From IP</th><th>Date</th><th>Duration</th>
        </tr></thead>
        <tbody>{rows_last()}</tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <span class="section-icon">🚫</span> Failed Logins (lastb)
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>User</th><th>TTY</th><th>From IP</th><th>Date</th>
        </tr></thead>
        <tbody>{rows_lastb()}</tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <span class="section-icon">🔒</span> Persistence Findings
    </div>
    <div class="anomaly-grid">
      {persistence_cards()}
    </div>
  </div>

</div>

<footer>
  AuthWatch &nbsp;·&nbsp; Generated: {generated[:19]} &nbsp;·&nbsp; Data from: last, lastb, lastlog, w
</footer>

{'<script>' + f"""
const ctx = document.getElementById('ipChart').getContext('2d');
new Chart(ctx, {{
  type: 'bar',
  data: {{
    labels: {chart_labels},
    datasets: [{{
      label: 'Failed attempts',
      data: {chart_values},
      backgroundColor: 'rgba(255,68,68,0.6)',
      borderColor: 'rgba(255,68,68,1)',
      borderWidth: 1,
      borderRadius: 4,
    }}]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: false,
    plugins: {{
      legend: {{ display: false }},
    }},
    scales: {{
      x: {{
        ticks: {{ color: '#6e7681', font: {{ family: 'JetBrains Mono', size: 10 }} }},
        grid: {{ color: 'rgba(30,45,61,0.8)' }},
      }},
      y: {{
        ticks: {{ color: '#6e7681', font: {{ family: 'JetBrains Mono', size: 10 }} }},
        grid: {{ color: 'rgba(30,45,61,0.8)' }},
        beginAtZero: true,
      }}
    }}
  }}
}});
""" + '</script>' if top_ips else ''}

</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n  📄  HTML report saved: {output_path}")
    return output_path
