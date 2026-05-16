#!/usr/bin/env python3
"""
Graph Visualizer v3.0 - Complete View Modes System
Integrates Risk Heatmap, Circular Layout, and all view modes
"""

import json
from pathlib import Path
from typing import Dict, List, Optional
import networkx as nx


class CompleteVisualizer:
    """Полный визуализатор с поддержкой всех режимов просмотра."""
    
    def __init__(self, graph: nx.DiGraph, rules: Optional[List] = None):
        self.graph = graph
        self.rules = rules or []
    
    def generate_html(self, output_path: Path, title: str = "Firewall Analysis") -> Path:
        """Генерирует HTML с полной поддержкой всех режимов."""
        
        nodes_data = []
        edges_data = []
        
        for node, data in self.graph.nodes(data=True):
            endpoint_type = data.get('endpoint_type', 'unknown')
            zone = data.get('zone', 'Unknown Zone')
            color_map = {'zone': '#90EE90', 'subnet': '#FFFACD', 'host': '#FFB6C1', 'group': '#87CEEB', 'unknown': '#D3D3D3'}
            nodes_data.append({'id': str(node), 'label': str(node), 'group': zone, 'type': endpoint_type, 'color': color_map.get(endpoint_type, '#D3D3D3'), 'size': 25, 'title': f"Type: {endpoint_type}<br>Zone: {zone}"})
        
        for src, dst, data in self.graph.edges(data=True):
            risk = data.get('risk_score', 0)
            color = '#666666'
            width = 1
            if risk >= 8: color = 'red'; width = 3
            elif risk >= 5: color = 'orange'; width = 2
            edges_data.append({'from': str(src), 'to': str(dst), 'color': color, 'width': width, 'risk': risk, 'title': f"Risk: {risk}/10"})
        
        rules_table = []
        for rule in self.rules[:100]:
            rules_table.append({'name': rule.name, 'sources': ', '.join(str(s) for s in rule.sources[:3]), 'destinations': ', '.join(str(d) for d in rule.destinations[:3]), 'services': ', '.join(str(s) for s in rule.services[:3]), 'action': rule.action})
        
        nodes_json = json.dumps(nodes_data, ensure_ascii=False)
        edges_json = json.dumps(edges_data, ensure_ascii=False)
        rules_json = json.dumps(rules_table, ensure_ascii=False)
        
        all_nodes = [n['id'] for n in nodes_data]
        zones = sorted(set(n.get('group', 'Other') for n in nodes_data))
        zones_options = '\n'.join(f'<option value="{z}">{z}</option>' for z in zones)
        
        html = f"""..."""  # Будет заменено ниже
        
        html = self._generate_html_content(title, nodes_json, edges_json, rules_json, all_nodes, zones_options, len(rules_table))
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return output_path
    
    def _generate_html_content(self, title, nodes_json, edges_json, rules_json, all_nodes, zones_options, rules_count):
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }}
        #header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 25px; box-shadow: 0 2px 10px rgba(0,0,0,0.2); }}
        #header h1 {{ margin: 0; font-size: 24px; font-weight: 300; }}
        #header p {{ margin: 5px 0 0; opacity: 0.9; font-size: 14px; }}
        #controls {{ background: white; padding: 10px 20px; display: flex; flex-wrap: wrap; align-items: center; gap: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        #controls label {{ font-weight: 600; color: #555; font-size: 13px; }}
        #controls input, #controls select {{ padding: 5px 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 13px; }}
        #controls button {{ padding: 5px 15px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; }}
        #controls button:hover {{ background: #5a6fd6; }}
        .mode-selector {{ display: flex; gap: 5px; margin-left: 10px; }}
        .mode-btn {{ padding: 5px 12px; border: 1px solid #ddd; background: #f5f5f5; border-radius: 4px; cursor: pointer; font-size: 12px; transition: all 0.2s; }}
        .mode-btn:hover {{ background: #e0e0e0; }}
        .mode-btn.active {{ background: #667eea; color: white; border-color: #667eea; }}
        #main-container {{ display: flex; height: calc(100vh - 140px); }}
        #mynetwork {{ flex: 1; background: white; position: relative; }}
        #sidebar {{ width: 450px; background: white; border-left: 1px solid #e0e0e0; padding: 20px; overflow-y: auto; }}
        #riskLegend {{ position: absolute; bottom: 20px; right: 20px; background: rgba(255,255,255,0.95); padding: 15px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.2); display: none; z-index: 1000; min-width: 200px; }}
        .risk-gradient {{ width: 100%; height: 20px; background: linear-gradient(to right, #00FF00 0%, #ADFF2F 30%, #FFD700 50%, #FF8C00 70%, #FF4500 80%, #FF0000 100%); border-radius: 10px; margin: 5px 0; }}
        .risk-categories {{ margin-top: 10px; }}
        .risk-categories div {{ display: flex; align-items: center; margin: 5px 0; font-size: 13px; }}
        .risk-dot {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; display: inline-block; }}
    </style>
</head>
<body>
    <div id="header"><h1>{title}</h1><p>Интерактивная карта | Все режимы просмотра</p></div>
    <div id="controls">
        <div><label>Режим:</label><select id="viewMode"><option value="access">Граф доступа</option><option value="topology">Топология</option></select></div>
        <div class="mode-selector">
            <button class="mode-btn active" onclick="changeMode('standard')">Стандарт</button>
            <button class="mode-btn" onclick="changeMode('hierarchical')">Иерархия</button>
            <button class="mode-btn" onclick="changeMode('circular')">Круг</button>
            <button class="mode-btn" onclick="changeMode('risk')">Риск</button>
        </div>
        <div><label>Поиск:</label><input type="text" id="nodeSearch" placeholder="Узел..."><button onclick="searchNode()">🔍</button></div>
        <div><label>Зона:</label><select id="zoneFilter" onchange="filterByZone()"><option value="all">Все</option>{zones_options}</select></div>
        <button onclick="resetAll()">Сбросить</button>
        <button onclick="exportGraph()">Экспорт</button>
    </div>
    <div id="main-container">
        <div id="mynetwork"></div>
        <div id="riskLegend"><h4>Уровни риска</h4><div class="risk-gradient"></div><div class="risk-categories">
            <div><span class="risk-dot" style="background:#00FF00"></span> Низкий (0-2)</div>
            <div><span class="risk-dot" style="background:#FFD700"></span> Средний (3-5)</div>
            <div><span class="risk-dot" style="background:#FF8C00"></span> Высокий (6-7)</div>
            <div><span class="risk-dot" style="background:#FF4500"></span> Критический (8-9)</div>
            <div><span class="risk-dot" style="background:#FF0000"></span> Опасный (10)</div>
        </div></div>
        <div id="sidebar"><h3>Правила ({rules_count})</h3><div id="rulesContainer"></div></div>
    </div>
<script>
const nodesData = {nodes_json};
const edgesData = {edges_json};
const rulesData = {rules_json};

const container = document.getElementById('mynetwork');
const data = {{ nodes: new vis.DataSet(nodesData), edges: new vis.DataSet(edgesData) }};

const options = {{
    nodes: {{ shape: 'dot', size: 25, font: {{ size: 14 }}, borderWidth: 2, shadow: {{ enabled: true, size: 10, x: 3, y: 3 }} }},
    edges: {{ width: 1, color: {{ color: '#666666', highlight: '#667eea', hover: '#667eea' }}, arrows: {{ to: {{ enabled: true, scaleFactor: 0.8 }} }}, smooth: {{ type: 'continuous' }}, shadow: {{ enabled: true, size: 5 }} }},
    physics: {{ enabled: true, forceAtlas2Based: {{ gravitationalConstant: -50, centralGravity: 0.01, springLength: 100, springConstant: 0.08 }}, solver: 'forceAtlas2Based', stabilization: {{ iterations: 1000 }} }},
    interaction: {{ hover: true, tooltipDelay: 200 }}
}};

const network = new vis.Network(container, data, options);

// View modes
let currentMode = 'standard';
let riskActive = false;
let originalColors = {{}};

function changeMode(mode) {{
    currentMode = mode;
    riskActive = mode === 'risk';
    document.getElementById('riskLegend').style.display = riskActive ? 'block' : 'none';
    
    document.querySelectorAll('.mode-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    
    if (mode === 'standard') applyStandard();
    else if (mode === 'hierarchical') applyHierarchical();
    else if (mode === 'circular') applyCircular();
    else if (mode === 'risk') applyRisk();
}}

function applyStandard() {{
    network.setOptions({{ layout: {{ hierarchical: false }}, physics: {{ enabled: true }} }});
    restoreColors();
}}

function applyHierarchical() {{
    network.setOptions({{
        layout: {{ hierarchical: {{ enabled: true, direction: 'UD', sortMethod: 'directed', levelSeparation: 150, nodeSpacing: 200 }} }},
        physics: {{ enabled: false }}
    }});
    restoreColors();
}}

function applyCircular() {{
    const n = nodesData.length;
    const radius = Math.max(400, n * 35);
    const groups = {{}};
    nodesData.forEach(node => {{
        const g = node.group || 'default';
        if (!groups[g]) groups[g] = [];
        groups[g].push(node);
    }});
    const groupNames = Object.keys(groups).sort();
    const sectorSize = (2 * Math.PI) / groupNames.length;
    
    let updates = [];
    groupNames.forEach((group, gi) => {{
        const nodes = groups[group];
        const start = gi * sectorSize;
        const end = (gi + 1) * sectorSize;
        nodes.forEach((node, ni) => {{
            const angle = start + (end - start) * (ni / Math.max(nodes.length, 1));
            const r = radius * (node.type === 'subnet' ? 0.7 : node.type === 'host' ? 0.85 : 1);
            updates.push({{ id: node.id, x: r * Math.cos(angle), y: r * Math.sin(angle) }});
        }});
    }});
    
    updates.forEach(u => network.moveNode(u.id, u.x, u.y));
    network.setOptions({{ physics: {{ enabled: false }} }});
    restoreColors();
}}

function applyRisk() {{
    if (Object.keys(originalColors).length === 0) {{
        nodesData.forEach(n => originalColors[n.id] = n.color);
    }}
    
    const nodeRisk = {{}};
    nodesData.forEach(n => nodeRisk[n.id] = 0);
    edgesData.forEach(e => {{
        nodeRisk[e.from] = Math.max(nodeRisk[e.from] || 0, e.risk || 0);
        nodeRisk[e.to] = Math.max(nodeRisk[e.to] || 0, e.risk || 0);
    }});
    
    const updates = nodesData.map(n => {{
        const risk = nodeRisk[n.id] || 0;
        return {{ id: n.id, color: {{ background: getRiskColor(risk), border: risk >= 8 ? '#8B0000' : '#666' }}, size: risk >= 8 ? 35 : 25 }};
    }});
    data.nodes.update(updates);
    
    const eUpdates = edgesData.map(e => ({{ id: e.id, color: {{ color: getRiskColor(e.risk || 0) }}, width: Math.max(1, (e.risk || 0) / 2) }}));
    data.edges.update(eUpdates);
}}

function getRiskColor(risk) {{
    if (risk <= 0) return '#00FF00';
    if (risk >= 10) return '#FF0000';
    const stops = [{{v:0,c:'#00FF00'}}, {{v:3,c:'#ADFF2F'}}, {{v:5,c:'#FFD700'}}, {{v:7,c:'#FF8C00'}}, {{v:8,c:'#FF4500'}}, {{v:10,c:'#FF0000'}}];
    for (let i = 0; i < stops.length - 1; i++) {{
        if (risk >= stops[i].v && risk <= stops[i+1].v) {{
            const t = (risk - stops[i].v) / (stops[i+1].v - stops[i].v);
            return interpolateColor(stops[i].c, stops[i+1].c, t);
        }}
    }}
    return '#FF0000';
}}

function interpolateColor(c1, c2, t) {{
    const hex2rgb = (hex) => ({{ r: parseInt(hex.slice(1,3),16), g: parseInt(hex.slice(3,5),16), b: parseInt(hex.slice(5,7),16) }});
    const a = hex2rgb(c1), b = hex2rgb(c2);
    const r = Math.round(a.r + t * (b.r - a.r));
    const g = Math.round(a.g + t * (b.g - a.g));
    const bl = Math.round(a.b + t * (b.b - a.b));
    return '#' + [r,g,bl].map(x => Math.max(0, Math.min(255, x)).toString(16).padStart(2,'0')).join('');
}}

function restoreColors() {{
    if (Object.keys(originalColors).length > 0) {{
        const updates = nodesData.map(n => ({{ id: n.id, color: originalColors[n.id] || '#97C2FC', size: 25 }}));
        data.nodes.update(updates);
        const eUpdates = edgesData.map(e => ({{ id: e.id, color: {{ color: '#666' }}, width: 1 }}));
        data.edges.update(eUpdates);
    }}
}}

function searchNode() {{
    const q = document.getElementById('nodeSearch').value.toLowerCase();
    const found = nodesData.find(n => n.id.toLowerCase().includes(q) || (n.label && n.label.toLowerCase().includes(q)));
    if (found) {{ network.focus(found.id, {{ scale: 1.5, animation: true }}); network.selectNodes([found.id]); }}
    else alert('Узел не найден');
}}

function filterByZone() {{
    const zone = document.getElementById('zoneFilter').value;
    data.nodes.update(nodesData.map(n => ({{ id: n.id, hidden: zone !== 'all' && n.group !== zone }})));
}}

function resetAll() {{
    document.getElementById('nodeSearch').value = '';
    document.getElementById('zoneFilter').value = 'all';
    data.nodes.update(nodesData.map(n => ({{ id: n.id, hidden: false }})));
    changeMode('standard');
    network.fit();
}}

function exportGraph() {{
    const canvas = container.getElementsByTagName('canvas')[0];
    const link = document.createElement('a');
    link.download = 'firewall-graph.png';
    link.href = canvas.toDataURL();
    link.click();
}}

// Fill rules table
let tableHtml = '<table id="rulesTable" style="width:100%;border-collapse:collapse;font-size:12px">';
tableHtml += '<tr style="background:#667eea;color:white"><th>Имя</th><th>Источник</th><th>Назначение</th><th>Сервис</th><th>Действие</th></tr>';
for (const rule of rulesData) {{
    tableHtml += `<tr><td>${{rule.name}}</td><td>${{rule.sources}}</td><td>${{rule.destinations}}</td><td>${{rule.services}}</td><td>${{rule.action}}</td></tr>`;
}}
tableHtml += '</table>';
document.getElementById('rulesContainer').innerHTML = tableHtml;

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {{
    if (e.target.tagName === 'INPUT') return;
    if (e.key === '1') changeMode('standard');
    if (e.key === '2') changeMode('hierarchical');
    if (e.key === '3') changeMode('circular');
    if (e.key === 'r' || e.key === 'R') changeMode('risk');
    if (e.key === 'Escape') resetAll();
}});

console.log('Visualizer v3.0 loaded - Nodes:', nodesData.length, 'Edges:', edgesData.length);
</script>
</body>
</html>"""


if __name__ == '__main__':
    g = nx.DiGraph()
    g.add_node('192.168.1.1', endpoint_type='host', zone='Inside')
    g.add_node('10.0.0.1', endpoint_type='host', zone='DMZ')
    g.add_node('0.0.0.0/0', endpoint_type='subnet', zone='Outside')
    g.add_edge('192.168.1.1', '10.0.0.1', risk_score=5)
    g.add_edge('10.0.0.1', '0.0.0.0/0', risk_score=8)
    
    viz = CompleteVisualizer(g)
    path = viz.generate_html(Path('output/test_v3.html'))
    print(f"Generated: {path} ({path.stat().st_size} bytes)")