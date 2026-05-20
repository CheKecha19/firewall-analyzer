with open('output/report.html', 'r', encoding='utf-8') as f:
    html = f.read()
print(f'Size: {len(html):,} bytes')

# Check which style is used
if 'tab-bar' in html or 'tab-content' in html:
    print('Style: NEW (tab-based)')
elif 'sidebar-panel' in html or 'info-panel' in html:
    print('Style: sidebar/panel based')
else:
    print('Style: OLD (basic)')

# Check for specific UI elements
for el in ['tab-dashboard', 'tab-rules', 'tab-audit', 'tab-mitre', 'minimap-canvas', 'drill-bread', 'path-panel', '3d-force-graph', 'toggleTheme', 'applyBranding']:
    found = el in html
    print(f'  {el}: {"YES" if found else "NO"}')
