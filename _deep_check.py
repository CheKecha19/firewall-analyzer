# -*- coding: utf-8 -*-
import re, json

with open(r'full_report.html', 'r', encoding='utf-8') as f:
    html = f.read()

print('=== Template Check ===')
if 'force-graph' in html or '3D-force-graph' in html:
    print('TEMPLATE: UI template (3D detected)')
elif 'ui_template' in html.lower():
    print('TEMPLATE: UI template referenced')
elif 'vis-network' in html and 'mynetwork' in html:
    print('TEMPLATE: Static HTML (vis-network)')
else:
    print('TEMPLATE: UNKNOWN')

print()
print('=== Title ===')
title_match = re.search(r'<title>(.*?)</title>', html)
print(f"Title: {title_match.group(1) if title_match else 'NOT FOUND'}")

print()
print('=== Key DOM Elements ===')
for el in ['mynetwork', 'tabBar', 'pathSource', 'pathTarget', 'nodeSearch', 'zone-filter', 'infoPanel']:
    print(f"  {el}: {'PRESENT' if el in html else 'MISSING'}")

print()
print('=== Data Injection ===')
nodes_match = re.search(r'nodesData = (\[.*?\]);', html, re.DOTALL)
if nodes_match:
    try:
        nodes = json.loads(nodes_match.group(1))
        print(f'  nodesData: {len(nodes)} nodes')
        if nodes:
            print(f'    Sample keys: {list(nodes[0].keys())}')
    except Exception as e:
        print(f'  nodesData parse error: {e}')
else:
    print('  nodesData: NOT FOUND')

edges_match = re.search(r'edgesData = (\[.*?\]);', html, re.DOTALL)
if edges_match:
    try:
        edges = json.loads(edges_match.group(1))
        print(f'  edgesData: {len(edges)} edges')
        if edges:
            print(f'    Sample keys: {list(edges[0].keys())}')
    except Exception as e:
        print(f'  edgesData parse error: {e}')
else:
    print('  edgesData: NOT FOUND')

rules_match = re.search(r'rulesData = (\[.*?\]);', html, re.DOTALL)
print(f'  rulesData: {bool(rules_match)}')

print()
print('=== JS Functions ===')
funcs = re.findall(r'function\s+(\w+)', html)
print(f'  {len(funcs)} functions: {funcs[:15]}...')

print()
print('=== Scripts ===')
scripts = re.findall(r'<script[^>]*>', html)
print(f'  Total script tags: {len(scripts)}')
for s in scripts:
    if 'src=' in s:
        src_match = re.search(r'src="([^"]+)"', s)
        if src_match:
            print(f'    External: {src_match.group(1)}')
    else:
        print(f'    Inline {s[:40]}...')
