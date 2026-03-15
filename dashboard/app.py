from flask import Flask, render_template_string, jsonify
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.models import Session, IOC, ThreatActor

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>OSINT Threat Intelligence Platform</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0d1117; color:#c9d1d9; font-family:monospace; padding:20px; }
  h1 { color:#58a6ff; font-size:1.4em; margin-bottom:20px; border-bottom:1px solid #21262d; padding-bottom:10px; }
  .stats { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:24px; }
  .stat-card { background:#161b22; border:1px solid #21262d; border-radius:8px; padding:16px; text-align:center; }
  .stat-card .num { font-size:2em; font-weight:bold; color:#58a6ff; }
  .stat-card .label { font-size:0.75em; color:#8b949e; margin-top:4px; }
  .stat-card.high .num { color:#f85149; }
  .stat-card.medium .num { color:#e3b341; }
  .stat-card.low .num { color:#3fb950; }
  table { width:100%; border-collapse:collapse; background:#161b22; border-radius:8px; overflow:hidden; }
  th { background:#21262d; color:#8b949e; padding:10px 14px; text-align:left; font-size:0.8em; text-transform:uppercase; }
  td { padding:10px 14px; border-top:1px solid #21262d; font-size:0.85em; }
  tr:hover td { background:#1c2129; }
  .badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:0.75em; }
  .badge.high { background:#3d1212; color:#f85149; }
  .badge.medium { background:#2d2208; color:#e3b341; }
  .badge.low { background:#0d2a12; color:#3fb950; }
  .badge.ipv4 { background:#0c2e4a; color:#58a6ff; }
  .badge.domain { background:#1a1e3a; color:#a371f7; }
  .badge.md5, .badge.sha256 { background:#2a1e08; color:#e3b341; }
  .badge.email { background:#1a2d1a; color:#3fb950; }
  .header-bar { display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; }
  h2 { color:#58a6ff; font-size:1em; }
  .refresh { color:#8b949e; font-size:0.75em; }
</style>
</head>
<body>
<h1>[ OSINT Threat Intelligence Platform ]</h1>

<div class="stats">
  <div class="stat-card"><div class="num">{{ total }}</div><div class="label">Total IOCs</div></div>
  <div class="stat-card high"><div class="num">{{ high }}</div><div class="label">High Severity</div></div>
  <div class="stat-card medium"><div class="num">{{ medium }}</div><div class="label">Medium Severity</div></div>
  <div class="stat-card low"><div class="num">{{ low }}</div><div class="label">Low Severity</div></div>
</div>

<div class="header-bar">
  <h2>Recent IOCs</h2>
  <span class="refresh">Auto-refresh: <a href="/" style="color:#58a6ff">reload</a></span>
</div>

<table>
  <thead>
    <tr>
      <th>IOC Value</th><th>Type</th><th>Source</th><th>Severity</th><th>MITRE ATT&CK</th><th>Discovered</th>
    </tr>
  </thead>
  <tbody>
    {% for ioc in iocs %}
    <tr>
      <td style="font-family:monospace;color:#e6edf3">{{ ioc.value[:60] }}</td>
      <td><span class="badge {{ ioc.ioc_type }}">{{ ioc.ioc_type }}</span></td>
      <td style="color:#8b949e">{{ ioc.source }}</td>
      <td><span class="badge {{ ioc.severity }}">{{ ioc.severity }}</span></td>
      <td style="color:#8b949e;font-size:0.78em">{{ ioc.mitre_tag[:60] if ioc.mitre_tag else '-' }}</td>
      <td style="color:#8b949e">{{ ioc.discovered_at.strftime('%Y-%m-%d %H:%M') }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
</body>
</html>
"""

@app.route("/")
def index():
    session = Session()
    iocs = session.query(IOC).order_by(IOC.discovered_at.desc()).limit(100).all()
    total = session.query(IOC).count()
    high = session.query(IOC).filter_by(severity="high").count()
    medium = session.query(IOC).filter_by(severity="medium").count()
    low = session.query(IOC).filter_by(severity="low").count()
    session.close()
    return render_template_string(TEMPLATE, iocs=iocs, total=total, high=high, medium=medium, low=low)

@app.route("/api/iocs")
def api_iocs():
    session = Session()
    iocs = session.query(IOC).order_by(IOC.discovered_at.desc()).limit(50).all()
    session.close()
    return jsonify([{
        "value": i.value, "type": i.ioc_type, "source": i.source,
        "severity": i.severity, "mitre": i.mitre_tag,
        "discovered": str(i.discovered_at)
    } for i in iocs])

def run_dashboard():
    app.run(host="127.0.0.1", port=5000, debug=False)
