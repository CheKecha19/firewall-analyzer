"""Check status of all features in firewall-analyzer."""
import re, os

base = os.path.dirname(os.path.abspath(__file__))

# 1. Check web_ui.py endpoints
with open(os.path.join(base, 'src/api/web_ui.py'), encoding='utf-8') as f:
    content = f.read()
endpoints = re.findall(r'@app\.(get|post)\("([^"]+)"\)', content)
print("=== REST API Endpoints ===")
for method, path in endpoints:
    print(f"  {method.upper():6s} {path}")

# 2. Check ui_template.html features
with open(os.path.join(base, 'src/api/ui_template.html'), encoding='utf-8') as f:
    html = f.read()
    
print("\n=== UI Template Features ===")
checks = {
    'tab-bar': 'tab-bar' in html,
    'tab-matrix': 'tab-matrix' in html,
    'tab-dashboard': 'tab-dashboard' in html,
    'tab-rules': 'tab-rules' in html,
    'tab-audit': 'tab-audit' in html,
    'tab-mitre': 'tab-mitre' in html,
    'tab-quality': 'tab-quality' in html,
    'tab-optimizer': 'tab-optimizer' in html,
    'drill-bread': 'drill-bread' in html,
    'drillToZone': 'drillToZone' in html,
    'resetDrillDown': 'resetDrillDown' in html,
    'pathEdges': 'pathEdges' in html,
    'animatePath': 'animatePath' in html,
    'blockedAt': 'blockedAt' in html,
    'minimap-canvas': 'minimap-canvas' in html,
    'drawMinimap': 'drawMinimap' in html or 'renderMinimap' in html,
    'fetch sankey': 'sankey' in html.lower(),
    'fetch zone-matrix': 'zone-matrix' in html.lower(),
}
for name, ok in checks.items():
    print(f"  [{'OK' if ok else 'MISS'}] {name}")

# 3. Check visualizer.py new methods
with open(os.path.join(base, 'src/graph/visualizer.py'), encoding='utf-8') as f:
    viz = f.read()

print("\n=== Visualizer Methods ===")
methods = [
    '_generate_sankey_data',
    '_generate_zone_matrix_data',
    '_generate_service_data',
    '_generate_risk_severity_data',
    '_generate_hilbert_data',
    '_hilbert_xy_to_d',
    '_hilbert_d_to_xy',
    '_hilbert_rot',
]
for m in methods:
    print(f"  [{'OK' if m in viz else 'MISS'}] {m}")

# 4. Check acl_parser.py
acl_path = os.path.join(base, 'src/parsers/acl_parser.py')
if os.path.exists(acl_path):
    with open(acl_path, encoding='utf-8') as f:
        acl = f.read()
    print("\n=== ACL Parser Features ===")
    checks2 = {
        'Aruba': 'aruba' in acl.lower(),
        'ip access-list session': 'ip access-list session' in acl.lower() or 'access-list session' in acl.lower(),
        'netservice': 'netservice' in acl.lower(),
        'netdestination': 'netdestination' in acl.lower(),
        'HP ProCurve': 'procurve' in acl.lower() or 'authorized-managers' in acl.lower(),
    }
    for name, ok in checks2.items():
        print(f"  [{'OK' if ok else 'MISS'}] {name}")
else:
    print("\n[WARN] acl_parser.py not found")

# 5. Quick lint check
print("\n=== Python Syntax Check ===")
import subprocess, sys
for f in ['src/graph/visualizer.py', 'src/api/web_ui.py', 'src/parsers/acl_parser.py']:
    fp = os.path.join(base, f)
    if os.path.exists(fp):
        r = subprocess.run([sys.executable, '-c', f'compile(open({fp!r}, encoding="utf-8").read(), {f!r}, "exec")'],
                         capture_output=True, text=True)
        print(f"  [{'OK' if r.returncode == 0 else 'ERR'}] {f} {'- syntax error!' if r.returncode != 0 else ''}")
        if r.stderr:
            print(f"    {r.stderr.strip()[:200]}")
