#!/usr/bin/env python3
"""
Risk Heatmap visualization for Firewall Analyzer
Canvas-based heatmap overlay with Gaussian blur
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import colorsys


class RiskHeatmap:
    """Тепловая карта рисков для узлов и рёбер графа."""
    
    # Цветовая шкала риска (0-10)
    RISK_COLORS = {
        0:  '#00FF00',  # Green - low
        3:  '#ADFF2F',  # Green-yellow
        5:  '#FFD700',  # Gold - medium
        7:  '#FF8C00',  # Dark orange - high
        8:  '#FF4500',  # Red-orange
        10: '#FF0000',  # Red - critical
    }
    
    def __init__(self, nodes_data: List[Dict], edges_data: List[Dict]):
        self.nodes = nodes_data
        self.edges = edges_data
        self.node_risk = {}
        self.edge_risk = {}
        self._calculate_risk()
    
    def _calculate_risk(self):
        """Рассчитать риск для каждого узла (max риск всех рёбер)."""
        # Инициализация
        for node in self.nodes:
            self.node_risk[node['id']] = 0
        
        # Риск рёбер
        for edge in self.edges:
            risk = edge.get('risk', 0)
            self.edge_risk[(edge['from'], edge['to'])] = risk
            
            # Агрегируем риск на узлы
            self.node_risk[edge['from']] = max(self.node_risk.get(edge['from'], 0), risk)
            self.node_risk[edge['to']] = max(self.node_risk.get(edge['to'], 0), risk)
    
    def get_risk_color(self, risk: float) -> str:
        """Получить цвет для значения риска (интерполяция)."""
        if risk <= 0:
            return self.RISK_COLORS[0]
        if risk >= 10:
            return self.RISK_COLORS[10]
        
        # Найти ближайшие точки
        levels = sorted(self.RISK_COLORS.keys())
        for i in range(len(levels) - 1):
            if levels[i] <= risk <= levels[i + 1]:
                # Интерполяция
                t = (risk - levels[i]) / (levels[i + 1] - levels[i])
                c1 = self._hex_to_rgb(self.RISK_COLORS[levels[i]])
                c2 = self._hex_to_rgb(self.RISK_COLORS[levels[i + 1]])
                r = int(c1[0] + t * (c2[0] - c1[0]))
                g = int(c1[1] + t * (c2[1] - c1[1]))
                b = int(c1[2] + t * (c2[2] - c1[2]))
                return f'#{r:02x}{g:02x}{b:02x}'
        
        return self.RISK_COLORS[10]
    
    def _hex_to_rgb(self, hex_color: str) -> Tuple[int, int, int]:
        """Конвертировать hex в RGB."""
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
    
    def generate_heatmap_js(self) -> str:
        """Сгенерировать JavaScript для тепловой карты."""
        nodes_risk_js = json.dumps(self.node_risk, ensure_ascii=False)
        edges_risk_js = json.dumps({f"{k[0]}->{k[1]}": v for k, v in self.edge_risk.items()}, ensure_ascii=False)
        
        return f"""
// Risk Heatmap Module
const nodeRiskScores = {nodes_risk_js};
const edgeRiskScores = {edges_risk_js};

function getRiskColor(risk) {{
    if (risk <= 0) return '#00FF00';
    if (risk >= 10) return '#FF0000';
    
    const stops = [
        {{v: 0, c: '#00FF00'}},
        {{v: 3, c: '#ADFF2F'}},
        {{v: 5, c: '#FFD700'}},
        {{v: 7, c: '#FF8C00'}},
        {{v: 8, c: '#FF4500'}},
        {{v: 10, c: '#FF0000'}}
    ];
    
    for (let i = 0; i < stops.length - 1; i++) {{
        if (risk >= stops[i].v && risk <= stops[i+1].v) {{
            const t = (risk - stops[i].v) / (stops[i+1].v - stops[i].v);
            const c1 = hexToRgb(stops[i].c);
            const c2 = hexToRgb(stops[i+1].c);
            return rgbToHex(
                Math.round(c1.r + t * (c2.r - c1.r)),
                Math.round(c1.g + t * (c2.g - c1.g)),
                Math.round(c1.b + t * (c2.b - c1.b))
            );
        }}
    }}
    return '#FF0000';
}}

function hexToRgb(hex) {{
    const result = /^#?([a-f\\d]{{2}})([a-f\\d]{{2}})([a-f\\d]{{2}})$/i.exec(hex);
    return result ? {{
        r: parseInt(result[1], 16),
        g: parseInt(result[2], 16),
        b: parseInt(result[3], 16)
    }} : {{r:0, g:0, b:0}};
}}

function rgbToHex(r, g, b) {{
    return '#' + [r, g, b].map(x => Math.max(0, Math.min(255, x)).toString(16).padStart(2, '0')).join('');
}}

function applyRiskHeatmap() {{
    // Обновить цвета узлов
    nodesData.forEach(node => {{
        const risk = nodeRiskScores[node.id] || 0;
        const color = getRiskColor(risk);
        node.color = {{
            background: color,
            border: risk >= 8 ? '#8B0000' : '#666666',
            highlight: {{
                background: color,
                border: '#000000'
            }}
        }};
        
        // Добавить пульсацию для critical
        if (risk >= 8) {{
            node.shape = 'dot';
            node.size = 35;
            // Добавить анимацию через CSS
        }} else {{
            node.size = 25;
        }}
    }});
    
    // Обновить рёбра
    edgesData.forEach(edge => {{
        const key = edge.from + '->' + edge.to;
        const risk = edgeRiskScores[key] || 0;
        const color = getRiskColor(risk);
        edge.color = {{
            color: color,
            highlight: color,
            hover: color
        }};
        edge.width = Math.max(1, risk / 2);
    }});
    
    // Обновить граф
    nodes.update(nodesData);
    edges.update(edgesData);
    
    // Обновить легенду
    updateRiskLegend();
}}

function updateRiskLegend() {{
    const legend = document.getElementById('riskLegend');
    if (!legend) return;
    
    legend.innerHTML = `
        <h4>Уровни риска</h4>
        <div class="risk-gradient"></div>
        <div class="risk-labels">
            <span>0</span>
            <span>5</span>
            <span>10</span>
        </div>
        <div class="risk-categories">
            <div><span class="risk-dot" style="background:#00FF00"></span> Низкий (0-2)</div>
            <div><span class="risk-dot" style="background:#FFD700"></span> Средний (3-5)</div>
            <div><span class="risk-dot" style="background:#FF8C00"></span> Высокий (6-7)</div>
            <div><span class="risk-dot" style="background:#FF4500"></span> Критический (8-9)</div>
            <div><span class="risk-dot" style="background:#FF0000"></span> Опасный (10)</div>
        </div>
    `;
    legend.style.display = 'block';
}}

function removeRiskHeatmap() {{
    // Восстановить оригинальные цвета
    nodesData.forEach(node => {{
        const originalColor = node.originalColor || '#97C2FC';
        node.color = originalColor;
        node.size = 25;
    }});
    
    edgesData.forEach(edge => {{
        edge.color = '#666666';
        edge.width = 1;
    }});
    
    nodes.update(nodesData);
    edges.update(edgesData);
    
    const legend = document.getElementById('riskLegend');
    if (legend) legend.style.display = 'none';
}}

// Canvas heatmap overlay (background)
function drawCanvasHeatmap() {{
    const canvas = document.getElementById('heatmapCanvas');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const container = document.getElementById('mynetwork');
    canvas.width = container.clientWidth;
    canvas.height = container.clientHeight;
    
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Получить позиции узлов
    const positions = network.getPositions();
    
    // Нарисовать radial gradient для каждого узла
    Object.entries(positions).forEach(([nodeId, pos]) => {{
        const risk = nodeRiskScores[nodeId] || 0;
        if (risk < 3) return; // Не рисуем для низкого риска
        
        const color = getRiskColor(risk);
        const rgb = hexToRgb(color);
        
        const gradient = ctx.createRadialGradient(
            pos.x, pos.y, 0,
            pos.x, pos.y, 100 * (risk / 10)
        );
        
        gradient.addColorStop(0, `rgba(${{rgb.r}}, ${{rgb.g}}, ${{rgb.b}}, 0.6)`);
        gradient.addColorStop(1, `rgba(${{rgb.r}}, ${{rgb.g}}, ${{rgb.b}}, 0)`);
        
        ctx.fillStyle = gradient;
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, 100 * (risk / 10), 0, 2 * Math.PI);
        ctx.fill();
    }});
}}
"""
    
    def get_risk_css(self) -> str:
        """CSS для тепловой карты."""
        return """
/* Risk Heatmap Styles */
.risk-gradient {
    width: 100%;
    height: 20px;
    background: linear-gradient(to right, 
        #00FF00 0%, 
        #ADFF2F 30%, 
        #FFD700 50%, 
        #FF8C00 70%, 
        #FF4500 80%, 
        #FF0000 100%
    );
    border-radius: 10px;
    margin: 5px 0;
}

.risk-labels {
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    color: #666;
}

.risk-categories {
    margin-top: 10px;
}

.risk-categories div {
    display: flex;
    align-items: center;
    margin: 5px 0;
    font-size: 13px;
}

.risk-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    margin-right: 8px;
    display: inline-block;
}

#riskLegend {
    position: absolute;
    bottom: 20px;
    right: 20px;
    background: rgba(255, 255, 255, 0.95);
    padding: 15px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    display: none;
    z-index: 1000;
    min-width: 200px;
}

#riskLegend h4 {
    margin: 0 0 10px 0;
    color: #333;
}

#heatmapCanvas {
    position: absolute;
    top: 0;
    left: 0;
    pointer-events: none;
    z-index: 1;
}

@keyframes pulse-critical {
    0% { transform: scale(1); opacity: 1; }
    50% { transform: scale(1.2); opacity: 0.8; }
    100% { transform: scale(1); opacity: 1; }
}

.node-critical {
    animation: pulse-critical 1s infinite;
}
"""


class CircularLayout:
    """Круговая раскладка узлов."""
    
    def __init__(self, nodes_data: List[Dict], edges_data: List[Dict]):
        self.nodes = nodes_data
        self.edges = edges_data
    
    def calculate_positions(self, center_x: float = 0, center_y: float = 0, 
                           radius: Optional[float] = None) -> Dict[str, Tuple[float, float]]:
        """Рассчитать позиции узлов по кругу."""
        n = len(self.nodes)
        if n == 0:
            return {}
        
        # Авто-радиус если не задан
        if radius is None:
            radius = max(300, n * 30)
        
        positions = {}
        
        # Сортировать узлы по зоне для группировки
        sorted_nodes = sorted(self.nodes, key=lambda n: n.get('group', '') + n['id'])
        
        for i, node in enumerate(sorted_nodes):
            angle = (2 * 3.14159 * i) / n  # Радианы
            x = center_x + radius * cos(angle)
            y = center_y + radius * sin(angle)
            positions[node['id']] = (x, y)
        
        return positions
    
    def generate_circular_js(self) -> str:
        """Сгенерировать JavaScript для круговой раскладки."""
        return """
// Circular Layout Module
function applyCircularLayout() {
    const nodeCount = nodesData.length;
    if (nodeCount === 0) return;
    
    const radius = Math.max(400, nodeCount * 35);
    const centerX = 0;
    const centerY = 0;
    
    // Группировать узлы по зонам
    const groups = {};
    nodesData.forEach(node => {
        const group = node.group || 'default';
        if (!groups[group]) groups[group] = [];
        groups[group].push(node);
    });
    
    const groupNames = Object.keys(groups).sort();
    const sectorSize = (2 * Math.PI) / groupNames.length;
    
    let positionUpdates = [];
    
    groupNames.forEach((group, groupIndex) => {
        const groupNodes = groups[group];
        const sectorStart = groupIndex * sectorSize;
        const sectorEnd = (groupIndex + 1) * sectorSize;
        
        // Концентрические круги для узлов внутри группы
        groupNodes.forEach((node, nodeIndex) => {
            const angle = sectorStart + (sectorEnd - sectorStart) * 
                         (nodeIndex / Math.max(groupNodes.length, 1));
            
            // Разные радиусы для разных типов узлов
            let nodeRadius = radius;
            if (node.type === 'subnet') nodeRadius *= 0.7;
            if (node.type === 'host') nodeRadius *= 0.85;
            
            const x = centerX + nodeRadius * Math.cos(angle);
            const y = centerY + nodeRadius * Math.sin(angle);
            
            positionUpdates.push({
                id: node.id,
                x: x,
                y: y
            });
        });
    });
    
    // Применить позиции
    network.setData({
        nodes: new vis.DataSet(nodesData.map(n => ({
            ...n,
            x: positionUpdates.find(p => p.id === n.id)?.x || n.x,
            y: positionUpdates.find(p => p.id === n.id)?.y || n.y
        }))),
        edges: edgesData
    });
    
    // Отключить физику
    network.setOptions({
        physics: {
            enabled: false
        }
    });
    
    // Центральный узел (gateway)
    const centerNode = nodesData.find(n => n.type === 'gateway' || n.group === 'Outside');
    if (centerNode) {
        network.moveNode(centerNode.id, centerX, centerY);
    }
    
    // Показать легенду секторов
    updateCircularLegend(groupNames);
}

function updateCircularLegend(groups) {
    const legend = document.getElementById('circularLegend');
    if (!legend) return;
    
    const colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE'];
    
    legend.innerHTML = `
        <h4>Секторы по зонам</h4>
        ${groups.map((g, i) => `
            <div style="display:flex;align-items:center;margin:5px 0">
                <span style="width:12px;height:12px;border-radius:50%;background:${colors[i % colors.length]};margin-right:8px"></span>
                <span>${g}</span>
            </div>
        `).join('')}
        <div style="margin-top:10px;font-size:12px;color:#666">
            Центр: Gateway / Core
        </div>
    `;
    legend.style.display = 'block';
}

function rotateCircular(degrees) {
    const positions = network.getPositions();
    const radians = degrees * (Math.PI / 180);
    
    Object.entries(positions).forEach(([nodeId, pos]) => {
        const x = pos.x * Math.cos(radians) - pos.y * Math.sin(radians);
        const y = pos.x * Math.sin(radians) + pos.y * Math.cos(radians);
        network.moveNode(nodeId, x, y);
    });
}
"""


def generate_complete_view_modes_js() -> str:
    """Сгенерировать полный JavaScript для всех режимов просмотра."""
    
    heatmap = RiskHeatmap([], [])
    circular = CircularLayout([], [])
    
    return f"""
// ============================================
// COMPLETE VIEW MODES SYSTEM v3.0
// ============================================

{heatmap.generate_heatmap_js()}

{circular.generate_circular_js()}

// View Mode Manager
const ViewModes = {{
    STANDARD: 'standard',
    HIERARCHICAL: 'hierarchical',
    CIRCULAR: 'circular',
    RISK_HEATMAP: 'risk',
    COMPLIANCE: 'compliance',
    PATH_TRACE: 'path',
    DIFF: 'diff',
    SERVICE_FILTER: 'service',
    TEMPORAL: 'temporal',
    COLLAPSED: 'collapsed'
}};

let currentMode = ViewModes.STANDARD;
let previousPositions = {{}};

function switchViewMode(mode) {{
    // Сохранить позиции
    if (network) {{
        previousPositions = network.getPositions();
    }}
    
    currentMode = mode;
    
    // Скрыть все специфичные легенды
    ['riskLegend', 'circularLegend', 'pathLegend'].forEach(id => {{
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    }});
    
    switch(mode) {{
        case ViewModes.STANDARD:
            applyStandardLayout();
            break;
        case ViewModes.HIERARCHICAL:
            applyHierarchicalLayout();
            break;
        case ViewModes.CIRCULAR:
            applyCircularLayout();
            break;
        case ViewModes.RISK_HEATMAP:
            applyStandardLayout();
            applyRiskHeatmap();
            break;
        case ViewModes.COMPLIANCE:
            applyComplianceView();
            break;
        case ViewModes.PATH_TRACE:
            // Path trace активируется через отдельный UI
            break;
        case ViewModes.DIFF:
            // Diff mode активируется через загрузку двух версий
            break;
        case ViewModes.SERVICE_FILTER:
            // Service filter через dropdown
            break;
        case ViewModes.TEMPORAL:
            // Temporal через timeline slider
            break;
        case ViewModes.COLLAPSED:
            toggleHierarchicalIp(true);
            break;
    }}
    
    // Обновить UI
    document.querySelectorAll('.mode-btn').forEach(btn => {{
        btn.classList.toggle('active', btn.dataset.mode === mode);
    }});
    
    // URL params
    const url = new URL(window.location);
    url.searchParams.set('mode', mode);
    window.history.replaceState({{}}, '', url);
}}

function applyStandardLayout() {{
    removeRiskHeatmap();
    
    network.setOptions({{
        layout: {{
            hierarchical: false
        }},
        physics: {{
            enabled: true,
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {{
                gravitationalConstant: -50,
                centralGravity: 0.01,
                springLength: 100,
                springConstant: 0.08
            }},
            stabilization: {{
                iterations: 1000
            }}
        }}
    }});
}}

function applyHierarchicalLayout() {{
    removeRiskHeatmap();
    
    network.setOptions({{
        layout: {{
            hierarchical: {{
                enabled: true,
                direction: 'UD',
                sortMethod: 'directed',
                levelSeparation: 150,
                nodeSpacing: 200
            }}
        }},
        physics: {{
            enabled: false
        }}
    }});
}}

function applyComplianceView() {{
    // Compliance overlay
    const violations = loadComplianceData(); // Загрузить из data-атрибута
    
    nodesData.forEach(node => {{
        const nodeViolations = violations[node.id] || [];
        if (nodeViolations.length > 0) {{
            const severity = Math.max(...nodeViolations.map(v => v.severity));
            node.color = {{
                border: getComplianceColor(severity),
                background: node.color.background || '#97C2FC'
            }};
            node.borderWidth = 3;
        }}
    }});
    
    nodes.update(nodesData);
}}

function getComplianceColor(severity) {{
    const colors = {{
        'critical': '#FF0000',
        'high': '#FF8C00',
        'medium': '#FFD700',
        'low': '#90EE90'
    }};
    return colors[severity] || '#666666';
}}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {{
    if (e.target.tagName === 'INPUT') return;
    
    switch(e.key) {{
        case '1': switchViewMode(ViewModes.STANDARD); break;
        case '2': switchViewMode(ViewModes.HIERARCHICAL); break;
        case '3': switchViewMode(ViewModes.CIRCULAR); break;
        case 'r': case 'R': switchViewMode(ViewModes.RISK_HEATMAP); break;
        case 'c': case 'C': switchViewMode(ViewModes.COMPLIANCE); break;
        case 'p': case 'P': document.getElementById('pathTraceBtn')?.click(); break;
        case 'd': case 'D': switchViewMode(ViewModes.DIFF); break;
        case 't': case 'T': switchViewMode(ViewModes.TEMPORAL); break;
    }}
}});

// Init mode from URL
const urlParams = new URLSearchParams(window.location.search);
const initialMode = urlParams.get('mode') || 'standard';
if (initialMode !== 'standard') {{
    // Применить после загрузки
    network.once('stabilizationIterationsDone', () => {{
        switchViewMode(initialMode);
    }});
}}
"""


if __name__ == '__main__':
    # Тест
    nodes = [
        {'id': 'A', 'group': 'Inside', 'type': 'subnet'},
        {'id': 'B', 'group': 'DMZ', 'type': 'host'},
        {'id': 'C', 'group': 'Outside', 'type': 'host'},
    ]
    edges = [
        {'from': 'A', 'to': 'B', 'risk': 8},
        {'from': 'B', 'to': 'C', 'risk': 5},
    ]
    
    heatmap = RiskHeatmap(nodes, edges)
    print("Risk Heatmap JS generated:", len(heatmap.generate_heatmap_js()), "chars")
    
    circular = CircularLayout(nodes, edges)
    print("Circular Layout JS generated:", len(circular.generate_circular_js()), "chars")
