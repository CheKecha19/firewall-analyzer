"""Check web UI template JS for errors."""
import re, json

with open('src/api/ui_template.html', 'r', encoding='utf-8') as f:
    html = f.read()

# Extract all JS
scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
all_js = '\n'.join(scripts)

print(f"Template size: {len(html):,} bytes")
print(f"JS size: {len(all_js):,} bytes")
print()

# ── Functions ──
print("=== Functions ===")
funcs = re.findall(r'function\s+(\w+)', all_js)
for f in sorted(funcs):
    print(f"  {f}()")

print()

# ── Event listeners ──
listeners = re.findall(r'addEventListener\(["\'](\w+)["\']', all_js)
print(f"Event listeners: {listeners}")

# ── API calls ──
print("\n=== API Calls ===")
fetches = re.findall(r'fetch\(["\']([^"\']+)["\']', all_js)
for f in fetches:
    print(f"  {f}")

# ── Data variables ──
print("\n=== Data Variables ===")
var_decls = re.findall(r'(?:var|let|const)\s+(\w+)', all_js)
for v in sorted(set(var_decls)):
    print(f"  {v}")

# ── Brace check ──
ob = all_js.count('{')
cb = all_js.count('}')
print(f"\nBraces: {ob} open / {cb} close", "OK" if ob == cb else f"MISMATCH by {abs(ob-cb)}")

# ── Key feature check ──
print("\n=== Feature Check ===")
features = {
    'tab switching': 'tab-bar' in html or ('data-tab=' in html and 'classList.add' in all_js),
    'tab-bar UI': 'tab-bar' in html,
    'drill-down (double-click zone)': 'drillToZone' in all_js,
    'drill breadcrumb': 'drill-bread' in html,
    'path trace animation': 'animatePath' in all_js and 'pathEdges' in all_js,
    'path blocked detection': 'blockedAt' in all_js,
    'minimap': 'minimap-canvas' in html,
    'Sankey loading': 'sankey' in all_js.lower(),
    'Zone matrix loading': 'zone-matrix' in all_js.lower(),
    'Service treemap loading': 'service' in all_js.lower() and 'fetch' in all_js.lower(),
    'Risk donut loading': 'risk-severity' in all_js.lower(),
    'Hilbert loading': 'hilbert' in all_js.lower(),
    'Dashboard loading': 'dashboard' in all_js.lower(),
    'Branding loading': 'branding' in all_js.lower(),
    'search with debounce': 'setTimeout' in all_js and 'search' in all_js.lower(),
}
for name, ok in features.items():
    print(f"  [{'OK' if ok else 'MISS'}] {name}")

# ── Potential errors ──
print("\n=== Potential Issues ===")
# Look for common JS mistakes
issues = []

# Event listener on non-existent elements
for m in re.finditer(r'document\.getElementById\(["\']([^"\']+)["\']\)\.addEventListener', all_js):
    el_id = m.group(1)
    if f'id="{el_id}"' not in html:
        issues.append(f"Listener on non-existent element: #{el_id}")

# fetch without error handling
fetch_calls = re.findall(r'fetch\([^)]+\)(?!\s*\.(?:then|catch))', all_js)
if fetch_calls:
    issues.append(f"fetch() without .then()/.catch(): {len(fetch_calls)} occurrences")

# Template literal issues (backticks)
backtick_count = all_js.count('`')
if backtick_count % 2 != 0:
    issues.append(f"Odd number of backticks: {backtick_count}")

for i in issues:
    print(f"  [WARN] {i}")
if not issues:
    print("  None obvious")
