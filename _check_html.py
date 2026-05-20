"""Deep check of generated HTML for JS/CSS/structural issues."""
import re
from collections import Counter

with open('output/test_check.html', 'r', encoding='utf-8') as f:
    html = f.read()

print(f"File size: {len(html):,} bytes")
print()

# ── 1. Structure ──
print("=== Structure ===")
print(f"  <script> blocks: {len(re.findall(r'<script', html))}")
print(f"  <style> blocks: {len(re.findall(r'<style', html))}")
print(f"  </html> present: {'</html>' in html}")

# Find all CSS classes used
classes = set(re.findall(r'class="([^"]*)"', html))
# Find all CSS class rules
css_rules = set()
for m in re.finditer(r'\.([a-zA-Z0-9_-]+)\s*[{,:]', html):
    css_rules.add(m.group(1))
used_no_def = [c.split() for c in classes if c]
used_flat = set()
for group in used_no_def:
    used_flat.update(group)
missing_css = used_flat - css_rules - {'hop'}

print(f"  CSS classes used: {len(used_flat)}")
print(f"  CSS rules defined: {len(css_rules)}")
if missing_css:
    # Filter out known external lib classes
    known_external = {'active', 'visible', 'hidden', 'label'}
    real_missing = missing_css - known_external
    if real_missing:
        print(f"  [WARN] Used but not defined: {sorted(real_missing)[:20]}")

# ── 2. Potential JS errors ──
print("\n=== JavaScript Analysis ===")

# Extract all JS (between <script> tags)
scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
all_js = '\n'.join(scripts)

# Check: vis-network CDN
if 'vis-network' in html:
    print("  [OK] vis-network CDN present")
else:
    print("  [ERR] vis-network CDN MISSING")

# Check: data injection
for var in ['nodesData', 'edgesData', 'rulesData']:
    if var in all_js:
        print(f"  [OK] {var} injected")
    else:
        print(f"  [ERR] {var} MISSING")

# Check: topo data
if 'topoNodes' in all_js:
    print("  [OK] topoNodes/topoEdges present")
else:
    print("  [INFO] topoNodes/topoEdges absent (no topology data for this test)")

# Check: function definitions
funcs = re.findall(r'function\s+(\w+)', all_js)
print(f"  Functions defined: {len(funcs)}")
key_funcs = ['initNetwork', 'showNodeInfo', 'applyFilters', 'tracePath', 'clearPath', 'drawChart']
for f in key_funcs:
    if f in funcs:
        print(f"    [OK] {f}()")
    else:
        print(f"    [MISS] {f}()")

# Check for undefined variable references (common mistakes)
# Look for variables used before assignment
simple_checks = {
    'allNodes': 'var allNodes' in all_js or 'let allNodes' in all_js or 'const allNodes' in all_js,
    'allEdges': 'var allEdges' in all_js or 'let allEdges' in all_js or 'const allEdges' in all_js,
    'network': 'var network' in all_js or 'let network' in all_js or 'const network' in all_js,
    'pathData': 'pathData' in all_js,
    'pathAnimationTimer': 'pathAnimationTimer' in all_js,
    'prevGraphState': 'prevGraphState' in all_js,
}
for var, ok in simple_checks.items():
    print(f"  [{'OK' if ok else 'MISS'}] {var} declared")

# Check: common JS pitfalls
pitfalls = []
# Using 'id' without wrapping in quotes in HTML
if re.search(r'(?<!"id")id\s*=', all_js):
    pitfalls.append("Potential: 'id =' used without quotes")
# Mismatched braces
open_braces = all_js.count('{')
close_braces = all_js.count('}')
if open_braces != close_braces:
    pitfalls.append(f"Brace mismatch: {open_braces} open vs {close_braces} close")

for p in pitfalls:
    print(f"  [WARN] {p}")

# ── 3. Tab/UI structure ──
print("\n=== UI Structure ===")
tab_ids = re.findall(r'id="(tab-[^"]+)"', html)
print(f"  Tab IDs: {tab_ids}")

# Check tab switching
if 'tab-content' in html:
    print("  [OK] tab-content class used")
if 'addEventListener' in all_js:
    click_handlers = len(re.findall(r'addEventListener.*click', all_js))
    print(f"  Click handlers: {click_handlers}")

# Check if filter controls exist
filter_checks = {
    'zone-filter': 'id="zone-filter"' in html,
    'risk-filter': 'risk' in html.lower() and 'filter' in html.lower(),
    'subnet-filter': 'subnet' in html.lower() and 'filter' in html.lower(),
    'search-box': 'search' in html.lower(),
}
for name, ok in filter_checks.items():
    print(f"  [{'OK' if ok else 'MISS'}] {name}")

# ── 4. Data integrity ──
print("\n=== Data Integrity ===")
# Extract and parse nodesData
node_match = re.search(r'var nodesData = (\[.*?\]);', all_js, re.DOTALL)
if node_match:
    import json
    try:
        nodes = json.loads(node_match.group(1))
        print(f"  nodesData: {len(nodes)} nodes")
        # Check required fields
        sample = nodes[0] if nodes else {}
        for field in ['id', 'label', 'group']:
            print(f"    [{'OK' if field in sample else 'MISS'}] node.{field}")
    except json.JSONDecodeError as e:
        print(f"  [ERR] nodesData parse error: {e}")

edge_match = re.search(r'var edgesData = (\[.*?\]);', all_js, re.DOTALL)
if edge_match:
    import json
    try:
        edges = json.loads(edge_match.group(1))
        print(f"  edgesData: {len(edges)} edges")
        sample = edges[0] if edges else {}
        for field in ['from', 'to']:
            print(f"    [{'OK' if field in sample else 'MISS'}] edge.{field}")
    except json.JSONDecodeError as e:
        print(f"  [ERR] edgesData parse error: {e}")

# ── 5. Topo view ──
print("\n=== Topology Views ===")
# These come from ui_template.html (web UI), not static HTML
# In static HTML, they'd need to be in _generate_full_html
topo_views = ['Logical', 'Physical', 'VLAN', 'Zone', 'Service', 'Data Flow', 'Trust Boundaries', 'Resilience']
if any(f'id="{v.lower().replace(" ", "-")}-view"' in html.lower() or v.lower().replace(' ', '-') in html.lower() for v in topo_views):
    print("  [OK] Topology views present")
else:
    print("  [WARN] Topology views not in static HTML (only in web UI template)")

# ── 6. Branding ──
print("\n=== Branding ===")
if 'branding.json' in all_js or 'branding' in all_js.lower():
    print("  [OK] Branding system referenced")
else:
    print("  [MISS] Branding not referenced in JS")

print("\n=== DONE ===")
