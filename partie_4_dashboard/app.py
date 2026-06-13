import argparse
import importlib.util
import json
import sqlite3
import sys
import sysconfig
from collections import Counter
from pathlib import Path


def preload_stdlib_code_module():
    if "code" in sys.modules and hasattr(sys.modules["code"], "InteractiveInterpreter"):
        return

    stdlib_code = Path(sysconfig.get_path("stdlib")) / "code.py"
    spec = importlib.util.spec_from_file_location("code", stdlib_code)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules["code"] = module


preload_stdlib_code_module()

from flask import Flask, render_template_string, request


BASE_DIR = Path(__file__).resolve().parents[1]
ALERTS_JSON = BASE_DIR / "alerts.json"
REPORT_JSON = BASE_DIR / "report.json"
ALERTS_DB = BASE_DIR / "alerts.db"

app = Flask(__name__)


def _load_json(path):
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _normalize_db_alert(row):
    details = row.get("details") or "{}"
    try:
        details = json.loads(details)
    except json.JSONDecodeError:
        details = {"raw": details}

    return {
        "timestamp": row.get("timestamp"),
        "severity": row.get("severity"),
        "alert_type": row.get("alert_type"),
        "source_ip": row.get("source_ip"),
        "dest_ip": row.get("dest_ip"),
        "details": details,
        "signature": row.get("signature"),
        "verified": row.get("verified"),
    }


def normalize_alert(alert):
    details = alert.get("details", {})
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except json.JSONDecodeError:
            details = {"raw": details}
    elif details is None:
        details = {}

    return {
        **alert,
        "details": details,
        "alert_type": alert.get("alert_type") or alert.get("rule") or "unknown",
        "source_ip": alert.get("source_ip") or alert.get("src_ip"),
        "dest_ip": alert.get("dest_ip") or alert.get("dst_ip"),
    }


def load_alerts():
    source = "none"
    alerts = []

    report = _load_json(REPORT_JSON)
    if report and isinstance(report, dict) and "report" in report:
        alerts = report.get("report", {}).get("alerts", [])
        source = "report.json"
    elif ALERTS_JSON.exists():
        alerts = _load_json(ALERTS_JSON) or []
        source = "alerts.json"
    elif ALERTS_DB.exists():
        conn = sqlite3.connect(ALERTS_DB)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC").fetchall()
        conn.close()
        alerts = [_normalize_db_alert(dict(row)) for row in rows]
        source = "alerts.db"

    return [normalize_alert(alert) for alert in alerts], source


def build_stats(alerts):
    severity_counts = Counter(alert.get("severity", "unknown") for alert in alerts)
    type_counts = Counter(alert.get("alert_type") or alert.get("rule") or "unknown" for alert in alerts)
    sources = Counter(alert.get("source_ip") or alert.get("src_ip") or "unknown" for alert in alerts)

    return {
        "total": len(alerts),
        "critical": severity_counts.get("critical", 0),
        "warning": severity_counts.get("warning", 0),
        "info": severity_counts.get("info", 0),
        "severity_counts": dict(severity_counts),
        "type_counts": type_counts.most_common(6),
        "top_sources": sources.most_common(5),
    }


def filter_alerts(alerts, severity, query):
    filtered = alerts
    if severity:
        filtered = [a for a in filtered if a.get("severity") == severity]
    if query:
        q = query.lower()
        filtered = [
            a for a in filtered
            if q in json.dumps(a, ensure_ascii=False).lower()
        ]
    return filtered


TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>TLS IDS Dashboard</title>
  <style>
    :root {
      --bg: #f6f8fb;
      --panel: #ffffff;
      --text: #1d2530;
      --muted: #687387;
      --border: #d8dee9;
      --critical: #b42318;
      --warning: #b76100;
      --info: #1261a6;
      --ok: #176b4d;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Arial, Helvetica, sans-serif;
      letter-spacing: 0;
    }

    header {
      border-bottom: 1px solid var(--border);
      background: var(--panel);
    }

    .wrap {
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
    }

    .top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 18px 0;
    }

    h1 {
      margin: 0;
      font-size: 22px;
      line-height: 1.2;
    }

    .source {
      color: var(--muted);
      font-size: 13px;
      white-space: nowrap;
    }

    main { padding: 22px 0 36px; }

    .stats {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }

    .stat {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
      min-height: 84px;
    }

    .stat span {
      display: block;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
    }

    .stat strong {
      display: block;
      margin-top: 8px;
      font-size: 28px;
      line-height: 1;
    }

    .filters {
      display: grid;
      grid-template-columns: 180px 1fr;
      gap: 12px;
      margin-bottom: 18px;
    }

    select,
    input {
      height: 40px;
      width: 100%;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0 11px;
      background: var(--panel);
      color: var(--text);
      font-size: 14px;
    }

    .grid {
      display: grid;
      grid-template-columns: 1fr 320px;
      gap: 16px;
      align-items: start;
    }

    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }

    .panel h2 {
      margin: 0;
      padding: 14px 16px;
      border-bottom: 1px solid var(--border);
      font-size: 15px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }

    th,
    td {
      padding: 11px 12px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
      font-size: 13px;
      word-break: break-word;
    }

    th {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      background: #fbfcfe;
    }

    tr:last-child td { border-bottom: 0; }

    .badge {
      display: inline-block;
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }

    .critical { color: var(--critical); background: #fdebea; }
    .warning { color: var(--warning); background: #fff4df; }
    .info { color: var(--info); background: #e8f3ff; }
    .unknown { color: var(--muted); background: #eef1f5; }

    .details {
      color: var(--muted);
      font-size: 12px;
      margin-top: 4px;
    }

    .side-list {
      padding: 12px 16px 16px;
    }

    .side-row {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 9px 0;
      border-bottom: 1px solid var(--border);
      font-size: 13px;
    }

    .side-row:last-child { border-bottom: 0; }
    .side-row span:first-child { color: var(--muted); }
    .side-row strong { text-align: right; }

    .empty {
      padding: 28px 16px;
      color: var(--muted);
      text-align: center;
      font-size: 14px;
    }

    @media (max-width: 820px) {
      .top,
      .filters,
      .grid {
        grid-template-columns: 1fr;
        display: grid;
      }

      .stats {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }

      .source { white-space: normal; }
    }
  </style>
</head>
<body>
  <header>
    <div class="wrap top">
      <h1>TLS IDS Dashboard</h1>
      <div class="source">Data source: {{ data_source }}</div>
    </div>
  </header>

  <main class="wrap">
    <section class="stats">
      <div class="stat"><span>Total alerts</span><strong>{{ stats.total }}</strong></div>
      <div class="stat"><span>Critical</span><strong>{{ stats.critical }}</strong></div>
      <div class="stat"><span>Warning</span><strong>{{ stats.warning }}</strong></div>
      <div class="stat"><span>Info</span><strong>{{ stats.info }}</strong></div>
    </section>

    <form class="filters" method="get">
      <select name="severity" aria-label="Severity">
        <option value="">All severities</option>
        {% for option in ["critical", "warning", "info"] %}
          <option value="{{ option }}" {% if severity == option %}selected{% endif %}>{{ option|title }}</option>
        {% endfor %}
      </select>
      <input name="q" value="{{ query }}" placeholder="Search IP, SNI, JA3, alert type">
    </form>

    <section class="grid">
      <div class="panel">
        <h2>Alerts</h2>
        {% if alerts %}
          <table>
            <thead>
              <tr>
                <th style="width: 120px;">Severity</th>
                <th style="width: 170px;">Type</th>
                <th>Flow</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {% for alert in alerts %}
                {% set severity_name = alert.get("severity", "unknown") %}
                {% set details = alert.get("details", {}) %}
                <tr>
                  <td><span class="badge {{ severity_name }}">{{ severity_name }}</span></td>
                  <td>{{ alert.get("alert_type") or alert.get("rule") or "unknown" }}</td>
                  <td>
                    {{ alert.get("source_ip") or alert.get("src_ip") or "unknown" }}
                    ->
                    {{ alert.get("dest_ip") or alert.get("dst_ip") or "unknown" }}
                    <div class="details">{{ alert.get("timestamp", "") }}</div>
                  </td>
                  <td>
                    {{ details.get("message") or alert.get("description") or "" }}
                    <div class="details">
                      SNI: {{ details.get("sni") or "N/A" }} |
                      JA3: {{ details.get("ja3") or alert.get("ja3") or "N/A" }}
                    </div>
                  </td>
                </tr>
              {% endfor %}
            </tbody>
          </table>
        {% else %}
          <div class="empty">No alerts found for the current filter.</div>
        {% endif %}
      </div>

      <aside class="panel">
        <h2>Alert Types</h2>
        <div class="side-list">
          {% for name, count in stats.type_counts %}
            <div class="side-row"><span>{{ name }}</span><strong>{{ count }}</strong></div>
          {% else %}
            <div class="side-row"><span>No data</span><strong>0</strong></div>
          {% endfor %}
        </div>
        <h2>Top Sources</h2>
        <div class="side-list">
          {% for name, count in stats.top_sources %}
            <div class="side-row"><span>{{ name }}</span><strong>{{ count }}</strong></div>
          {% else %}
            <div class="side-row"><span>No data</span><strong>0</strong></div>
          {% endfor %}
        </div>
      </aside>
    </section>
  </main>
</body>
</html>
"""


@app.route("/")
def dashboard():
    alerts, source = load_alerts()
    severity = request.args.get("severity", "").strip()
    query = request.args.get("q", "").strip()
    filtered = filter_alerts(alerts, severity, query)

    return render_template_string(
        TEMPLATE,
        alerts=filtered,
        stats=build_stats(alerts),
        data_source=source,
        severity=severity,
        query=query,
    )


def main():
    parser = argparse.ArgumentParser(description="Run the local TLS IDS dashboard.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=5000, type=int)
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
