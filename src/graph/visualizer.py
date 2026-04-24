"""
Профессиональный визуализатор графа с интерактивными элементами управления.
"""
import json
import base64
from pathlib import Path
from typing import Optional, Dict, List, Set, Tuple
import networkx as nx
from ..models.rule import FirewallRule


class GraphVisualizer:
    """Продвинутый визуализатор сетевого графа с кластеризацией и фильтрацией."""
    
    NODE_COLORS = {
        'zone': '#90EE90',
        'subnet': '#FFFACD',
        'host': '#FFB6C1',
        'group': '#87CEEB',
        'unknown': '#D3D3D3',
    }
    
    RISK_COLORS = {
        0: '#00FF00',   # Green - low risk
        5: '#FFD700',   # Gold - medium risk
        8: '#FF8C00',   # Dark orange - high risk
        10: '#FF0000',  # Red - critical
    }
    
    def __init__(self, graph: nx.DiGraph, rules: Optional[List[FirewallRule]] = None):
        self.graph = graph
        self.rules = rules or []
        self.zones: Set[str] = set()
        self._extract_zones()
    
    def _extract_zones(self):
        """Извлекает все зоны из графа."""
        for node, data in self.graph.nodes(data=True):
            zone = data.get('zone')
            if zone:
                self.zones.add(zone)
        
        # Если зон нет, создаём их на основе имен узлов
        if not self.zones:
            # Определяем зоны по типам endpoint'ов
            for node, data in self.graph.nodes(data=True):
                ep_type = data.get('endpoint_type', 'unknown')
                if ep_type == 'subnet' or ('/' in str(node) and self._is_ip_network(str(node))):
                    zone = 'Network'
                elif ep_type == 'host' or self._is_ip(str(node)):
                    zone = 'Host'
                elif 'any' in str(node).lower():
                    zone = 'Any'
                else:
                    zone = 'Other'
                
                self.zones.add(zone)
                # Обновляем данные узла
                data['zone'] = zone
    
    def _is_ip(self, value: str) -> bool:
        """Проверяет, является ли строка IP-адресом."""
        import re
        return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value))
    
    def _is_ip_network(self, value: str) -> bool:
        """Проверяет, является ли строка IP-сетью."""
        import re
        return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}/\d+$', value))
    
    def generate_png(self, output_path: Path) -> Optional[Path]:
        """Генерирует статическое PNG изображение через Graphviz."""
        try:
            import pygraphviz as pgv
            
            A = nx.nx_agraph.to_agraph(self.graph)
            
            A.graph_attr['rankdir'] = 'LR'
            A.graph_attr['bgcolor'] = 'white'
            A.graph_attr['splines'] = 'true'
            A.graph_attr['overlap'] = 'false'
            
            A.node_attr['shape'] = 'box'
            A.node_attr['style'] = 'filled'
            A.node_attr['fontname'] = 'Arial'
            A.node_attr['fontsize'] = '10'
            
            # Применяем цвета к узлам
            for node in A.nodes():
                node_obj = A.get_node(node)
                endpoint_type = self.graph.nodes.get(node, {}).get('endpoint_type', 'unknown')
                node_obj.attr['fillcolor'] = self.NODE_COLORS.get(endpoint_type, self.NODE_COLORS['unknown'])
            
            # Применяем цвета к рёбрам по риску
            for edge in A.edges():
                edge_obj = A.get_edge(edge[0], edge[1])
                src, dst = edge[0], edge[1]
                if self.graph.has_edge(src, dst):
                    risk = self.graph[src][dst].get('risk_score', 0)
                    if risk >= 8:
                        edge_obj.attr['color'] = 'red'
                        edge_obj.attr['penwidth'] = '3'
                    elif risk >= 5:
                        edge_obj.attr['color'] = 'orange'
                        edge_obj.attr['penwidth'] = '2'
            
            A.draw(str(output_path), prog='dot', format='png')
            return output_path
            
        except ImportError:
            try:
                import matplotlib.pyplot as plt
                import matplotlib.patches as mpatches
                
                plt.figure(figsize=(20, 16))
                
                pos = nx.spring_layout(self.graph, k=3, iterations=100, seed=42)
                
                # Цвета узлов
                node_colors = []
                for node in self.graph.nodes():
                    endpoint_type = self.graph.nodes[node].get('endpoint_type', 'unknown')
                    node_colors.append(self.NODE_COLORS.get(endpoint_type, self.NODE_COLORS['unknown']))
                
                # Цвета рёбер по риску
                edge_colors = []
                for src, dst in self.graph.edges():
                    risk = self.graph[src][dst].get('risk_score', 0)
                    if risk >= 8:
                        edge_colors.append('red')
                    elif risk >= 5:
                        edge_colors.append('orange')
                    else:
                        edge_colors.append('gray')
                
                nx.draw_networkx_nodes(self.graph, pos, node_color=node_colors, 
                                      node_size=2500, alpha=0.9, linewidths=2, edgecolors='black')
                nx.draw_networkx_edges(self.graph, pos, edge_color=edge_colors, 
                                      arrows=True, arrowsize=25, width=1.5, 
                                      connectionstyle='arc3,rad=0.1')
                nx.draw_networkx_labels(self.graph, pos, font_size=9, font_weight='bold')
                
                # Легенда
                legend_elements = [
                    mpatches.Patch(color=color, label=node_type.title())
                    for node_type, color in self.NODE_COLORS.items()
                ]
                plt.legend(handles=legend_elements, loc='upper right', fontsize=10)
                
                plt.title('Firewall Access Map', fontsize=16, fontweight='bold')
                plt.axis('off')
                plt.tight_layout()
                plt.savefig(str(output_path), dpi=150, bbox_inches='tight', facecolor='white')
                plt.close()
                
                return output_path
                
            except ImportError:
                print("[WARN] pygraphviz or matplotlib not installed. PNG not generated.")
                return None
    
    def generate_html(self, output_path: Path, title: str = "Firewall Access Map",
                       topology_data: Optional[Tuple[List[Dict], List[Dict]]] = None) -> Optional[Path]:
        """Генерирует интерактивный HTML с кластеризацией и фильтрами."""
        try:
            # Подготавливаем данные для vis-network
            nodes_data = []
            for node, data in self.graph.nodes(data=True):
                endpoint_type = data.get('endpoint_type', 'unknown')
                zone = data.get('zone', 'Unknown Zone')
                color = self.NODE_COLORS.get(endpoint_type, self.NODE_COLORS['unknown'])
                size = 30 if endpoint_type == 'zone' else 25
                
                nodes_data.append({
                    'id': node,
                    'label': node,
                    'group': zone,
                    'color': color,
                    'size': size,
                    'title': f"Тип: {endpoint_type}<br>Зона: {zone}"
                })
            
            edges_data = []
            for src, dst, data in self.graph.edges(data=True):
                risk = data.get('risk_score', 0)
                rule_names = data.get('rules', [])
                
                if risk >= 8:
                    color = 'red'
                    width = 4
                elif risk >= 5:
                    color = 'orange'
                    width = 2
                else:
                    color = '#666666'
                    width = 1
                
                edge_title = f"Risk: {risk}/10"
                if rule_names:
                    edge_title += f"<br>Rules: {', '.join(rule_names[:3])}"
                    if len(rule_names) > 3:
                        edge_title += f" (+{len(rule_names) - 3})"
                
                edges_data.append({
                    'from': src,
                    'to': dst,
                    'color': color,
                    'width': width,
                    'title': edge_title
                })
            
            # Собираем данные для таблицы правил
            rules_table = []
            for rule in self.rules[:100]:
                rules_table.append({
                    'name': rule.name,
                    'sources': ', '.join(s.name for s in rule.sources[:3]),
                    'destinations': ', '.join(d.name for d in rule.destinations[:3]),
                    'services': ', '.join(s.name for s in rule.services[:3]),
                    'action': rule.action
                })
            
            # Генерируем полный HTML
            html_content = self._generate_full_html(
                title, nodes_data, edges_data, rules_table, topology_data=topology_data
            )
            
            # Записываем HTML
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return output_path
            
        except Exception as e:
            print(f"[WARN] Error generating HTML: {e}")
            return self._generate_fallback_html(output_path, title)
    
    def _generate_full_html(self, title: str, nodes_data: List[Dict], 
                           edges_data: List[Dict], rules_table: List[Dict],
                           topology_data: Optional[Tuple[List[Dict], List[Dict]]] = None) -> str:
        """Генерирует полный HTML с встроенным vis-network."""
        
        # Группируем узлы по подсетям (по третьему октету)
        nodes_with_subnets = self._group_nodes_by_subnet(nodes_data)
        
        nodes_json = json.dumps(nodes_with_subnets, ensure_ascii=False)
        edges_json = json.dumps(edges_data, ensure_ascii=False)
        rules_json = json.dumps(rules_table, ensure_ascii=False)
        
        # Подготавливаем данные топологии (если есть)
        if topology_data:
            topo_nodes_json = json.dumps(topology_data[0], ensure_ascii=False)
            topo_edges_json = json.dumps(topology_data[1], ensure_ascii=False)
        else:
            topo_nodes_json = '[]'
            topo_edges_json = '[]'
        
        # Генерируем опции зон с группировкой
        zones_options = self._generate_zone_options(nodes_with_subnets)
        
        # Собираем уникальные подсети
        subnets = sorted(set(n.get('subnet') for n in nodes_with_subnets if n.get('subnet') != 'Other'))
        subnet_options = ''.join(f'<option value="{s}">{s}</option>' for s in subnets)
        
        # Собираем список всех узлов для автокомплита
        all_nodes = [n['id'] for n in nodes_with_subnets]
        nodes_list_json = json.dumps(all_nodes, ensure_ascii=False)
        
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }}
        
        #header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
        }}
        #header h1 {{ margin: 0; font-size: 24px; font-weight: 300; }}
        #header p {{ margin: 5px 0 0 0; opacity: 0.9; font-size: 14px; }}
        
        #controls {{
            background: white;
            padding: 15px 25px;
            border-bottom: 1px solid #ddd;
            display: flex;
            gap: 20px;
            align-items: center;
            flex-wrap: wrap;
        }}
        #controls label {{ font-weight: 600; color: #333; margin-right: 5px; }}
        #controls select, #controls input {{
            padding: 8px 12px;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 14px;
        }}
        #controls button {{
            padding: 8px 16px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.2s;
        }}
        #controls button:hover {{ background: #5568d3; }}
        #controls button.secondary {{ background: #6c757d; }}
        #controls button.secondary:hover {{ background: #5a6268; }}
        
        #main-container {{
            display: flex;
            height: calc(100vh - 160px);
        }}
        
        #mynetwork {{
            flex: 1;
            background: white;
            border: 1px solid #ddd;
        }}
        
        #sidebar {{
            width: 450px;
            background: white;
            border-left: 1px solid #ddd;
            display: none;
            flex-direction: column;
        }}
        #sidebar.visible {{ display: flex; }}
        
        #sidebar h3 {{
            margin: 0;
            padding: 15px;
            background: #f8f9fa;
            border-bottom: 1px solid #ddd;
            font-size: 16px;
        }}
        
        #rulesTableContainer {{
            flex: 1;
            overflow: auto;
            padding: 10px;
        }}
        
        #rulesTable {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }}
        #rulesTable th {{
            background: #667eea;
            color: white;
            padding: 10px;
            text-align: left;
            position: sticky;
            top: 0;
        }}
        #rulesTable td {{
            padding: 8px 10px;
            border-bottom: 1px solid #eee;
            max-width: 150px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        #rulesTable tr:hover {{ background: #f5f5f5; cursor: pointer; }}
        #rulesTable tr.selected {{ background: #e3f2fd; }}
        
        #legend {{
            position: fixed;
            top: 160px;
            right: 20px;
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.15);
            z-index: 100;
            font-size: 12px;
        }}
        #legend h4 {{ margin: 0 0 10px 0; font-size: 13px; }}
        .legend-item {{ display: flex; align-items: center; margin: 5px 0; }}
        .legend-color {{
            width: 16px;
            height: 16px;
            margin-right: 8px;
            border-radius: 3px;
            border: 1px solid #999;
        }}
        
        #pathMessage {{
            position: fixed;
            top: 80px;
            left: 50%;
            transform: translateX(-50%);
            background: #28a745;
            color: white;
            padding: 10px 20px;
            border-radius: 4px;
            display: none;
            z-index: 1000;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
        }}
        
        #infoPanel {{
            position: fixed;
            top: 160px;
            right: 20px;
            width: 300px;
            max-height: 400px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.15);
            z-index: 100;
            display: none;
            overflow: auto;
            font-size: 12px;
        }}
        #infoPanel.visible {{ display: block; }}
        #infoPanel h4 {{
            margin: 0;
            padding: 12px 15px;
            background: #667eea;
            color: white;
            font-size: 13px;
            border-radius: 8px 8px 0 0;
        }}
        #infoPanel .info-content {{
            padding: 15px;
        }}
        #infoPanel .info-row {{
            margin-bottom: 8px;
            padding-bottom: 8px;
            border-bottom: 1px solid #eee;
        }}
        #infoPanel .info-label {{
            font-weight: 600;
            color: #666;
            margin-bottom: 2px;
        }}
        #infoPanel .info-value {{
            color: #333;
            word-break: break-all;
        }}
        #infoPanel .close-btn {{
            position: absolute;
            top: 10px;
            right: 10px;
            color: white;
            cursor: pointer;
            font-size: 16px;
        }}
        
        /* Dark theme */
        body.dark-theme {{
            background: #1a1a2e;
            color: #eee;
        }}
        body.dark-theme #header {{
            background: linear-gradient(135deg, #16213e 0%, #0f3460 100%);
        }}
        body.dark-theme #controls {{
            background: #16213e;
            border-bottom-color: #0f3460;
        }}
        body.dark-theme #controls label {{
            color: #eee;
        }}
        body.dark-theme #mynetwork {{
            background: #1a1a2e;
            border-color: #0f3460;
        }}
        body.dark-theme #sidebar {{
            background: #16213e;
            border-left-color: #0f3460;
        }}
        body.dark-theme #sidebar h3 {{
            background: #0f3460;
            color: #eee;
        }}
        body.dark-theme #legend,
        body.dark-theme #infoPanel {{
            background: #16213e;
            color: #eee;
        }}
        body.dark-theme #infoPanel h4 {{
            background: #0f3460;
        }}
        body.dark-theme #infoPanel .info-label {{
            color: #aaa;
        }}
        body.dark-theme #infoPanel .info-value {{
            color: #eee;
        }}
        body.dark-theme #infoPanel .info-row {{
            border-bottom-color: #0f3460;
        }}
        
        .checkbox-label {{ display: flex; align-items: center; gap: 5px; }}
        
        /* Hierarchical IP Groups styling */
        .vis-network .group-octet1 {{ background: rgba(227, 242, 253, 0.3); border-radius: 8px; }}
        .vis-network .group-octet2 {{ background: rgba(187, 222, 251, 0.3); border-radius: 6px; }}
        .vis-network .group-octet3 {{ background: rgba(144, 202, 249, 0.3); border-radius: 4px; }}
    </style>
</head>
<body>
    <div id="header">
        <h1>{title}</h1>
        <p>Интерактивная карта сетевого доступа | Наведите на узлы для деталей</p>
    </div>
    
    <div id="controls">
        <div>
            <label>Режим:</label>
            <select id="viewMode" onchange="switchViewMode()">
                <option value="access">Граф доступа</option>
                <option value="topology">Топология сети</option>
            </select>
        </div>
        
        <div>
            <label>Поиск узла:</label>
            <input type="text" id="nodeSearch" list="nodesList" placeholder="Введите имя узла...">
            <button onclick="searchNode()">🔍</button>
        </div>
        
        <div>
            <label>Фильтр по зоне:</label>
            <select id="zoneFilter" onchange="filterByZone()">
                <option value="all">📋 Все зоны</option>
                {zones_options}
            </select>
        </div>
        
        <div>
            <label>Фильтр по подсети:</label>
            <select id="subnetFilter" onchange="filterBySubnet()">
                <option value="all">Все подсети</option>
                {subnet_options}
            </select>
        </div>
        
        <div>
            <label>Поиск пути:</label>
            <input type="text" id="pathSource" list="nodesList" placeholder="Откуда" style="width: 120px;">
            <span> → </span>
            <input type="text" id="pathTarget" list="nodesList" placeholder="Куда" style="width: 120px;">
            <button onclick="findPath()">Найти</button>
            <datalist id="nodesList">
                {''.join(f'<option value="{n}">' for n in all_nodes)}
            </datalist>
        </div>
        
        <div>
            <label>Раскладка:</label>
            <select id="layoutMode" onchange="changeLayout()">
                <option value="standard">Стандартная</option>
                <option value="hierarchical">Иерархическая</option>
                <option value="circular">Круговая</option>
            </select>
        </div>
        
        <div class="checkbox-label">
            <input type="checkbox" id="physicsEnabled" checked onchange="togglePhysics()">
            <label for="physicsEnabled">Физика</label>
        </div>
        
        <div class="checkbox-label">
            <input type="checkbox" id="hierarchicalIp" onchange="toggleHierarchicalIp()">
            <label for="hierarchicalIp">Группировка IP по октетам</label>
        </div>
        
        <div class="checkbox-label">
            <input type="checkbox" id="showHighRisk" checked onchange="toggleRiskView()">
            <label for="showHighRisk">Только высокий риск</label>
        </div>
        
        <button onclick="resetFilters()" class="secondary">Сбросить</button>
        <button onclick="toggleRulesTable()">Таблица правил</button>
        <button onclick="exportGraph()">Экспорт PNG</button>
        <button onclick="toggleTheme()" class="secondary">🌓 Тема</button>
    </div>
    
    <div id="pathMessage"></div>
    
    <div id="main-container">
        <div id="mynetwork"></div>
        
        <div id="sidebar">
            <h3>Правила файрвола ({len(rules_table)})</h3>
            <div id="rulesTableContainer">
                <table id="rulesTable">
                    <thead>
                        <tr>
                            <th>Имя</th>
                            <th>Источник</th>
                            <th>Назначение</th>
                            <th>Сервис</th>
                            <th>Действие</th>
                        </tr>
                    </thead>
                    <tbody id="rulesTableBody"></tbody>
                </table>
            </div>
        </div>
    </div>
    
    <div id="legend">
        <h4>Типы узлов</h4>
        <div class="legend-item">
            <div class="legend-color" style="background: {self.NODE_COLORS['zone']}"></div>
            <span>Зона</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: {self.NODE_COLORS['subnet']}"></div>
            <span>Подсеть</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: {self.NODE_COLORS['host']}"></div>
            <span>Хост</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: {self.NODE_COLORS['group']}"></div>
            <span>Группа</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: {self.NODE_COLORS['unknown']}"></div>
            <span>Неизвестно</span>
        </div>
        <h4 style="margin-top: 15px;">Уровни риска</h4>
        <div class="legend-item">
            <div class="legend-color" style="background: #FF0000"></div>
            <span>Критический (8-10)</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #FF8C00"></div>
            <span>Высокий (5-7)</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #00FF00"></div>
            <span>Низкий (0-4)</span>
        </div>
    </div>
    
    <!-- Info Panel -->
    <div id="infoPanel">
        <span class="close-btn" onclick="closeInfoPanel()">×</span>
        <h4 id="infoPanelTitle">Детали узла/соединения</h4>
        <div class="info-content" id="infoPanelContent">
            <p>Кликните на узел или соединение для просмотра деталей</p>
        </div>
    </div>
    
    <script type="text/javascript">
        // Данные графа
        const nodesData = {nodes_json};
        const edgesData = {edges_json};
        const rulesData = {rules_json};
        const allNodes = {nodes_list_json};
        
        // Данные топологии
        const topologyData = {{ nodes: {topo_nodes_json}, edges: {topo_edges_json} }};
        
        // Создаём сеть
        const container = document.getElementById('mynetwork');
        const data = {{
            nodes: new vis.DataSet(nodesData),
            edges: new vis.DataSet(edgesData)
        }};
        
        const options = {{
            nodes: {{
                borderWidth: 2,
                borderWidthSelected: 4,
                shadow: {{ enabled: true, size: 10, x: 5, y: 5 }},
                font: {{ size: 14, face: 'Segoe UI' }}
            }},
            edges: {{
                smooth: {{ type: 'curvedCW', roundness: 0.2 }},
                shadow: {{ enabled: true, size: 5, x: 3, y: 3 }},
                arrows: {{ to: {{ enabled: true, scaleFactor: 1 }} }}
            }},
            interaction: {{
                hover: true,
                tooltipDelay: 200
            }},
            physics: {{
                enabled: true,
                forceAtlas2Based: {{
                    gravitationalConstant: -50,
                    centralGravity: 0.01,
                    springLength: 200,
                    springConstant: 0.08,
                    damping: 0.4
                }},
                solver: 'forceAtlas2Based'
            }},
            groups: {{
                useDefaultGroups: false
            }}
        }};
        
        const network = new vis.Network(container, data, options);
        
        // Функция фильтрации по зоне
        function filterByZone() {{
            const selectedValue = document.getElementById('zoneFilter').value;
            
            if (selectedValue === 'all') {{
                // Показываем все узлы
                data.nodes.forEach(node => {{
                    data.nodes.update({{ id: node.id, hidden: false }});
                }});
                network.fit();
                return;
            }}
            
            // Разбираем значение (subnet:xxx или zone:xxx)
            const [filterType, filterValue] = selectedValue.includes(':') 
                ? selectedValue.split(':') 
                : ['zone', selectedValue];
            
            // Фильтруем узлы
            const nodesToShow = [];
            data.nodes.forEach(node => {{
                let shouldShow = false;
                
                if (filterType === 'subnet') {{
                    // Фильтр по подсети
                    shouldShow = node.subnet === filterValue;
                }} else {{
                    // Фильтр по зоне
                    shouldShow = node.group === filterValue;
                }}
                
                if (shouldShow) {{
                    nodesToShow.push(node.id);
                    data.nodes.update({{ id: node.id, hidden: false }});
                }} else {{
                    data.nodes.update({{ id: node.id, hidden: true }});
                }}
            }});
            
            // Скрываем рёбра к скрытым узлам
            data.edges.forEach(edge => {{
                const fromVisible = !data.nodes.get(edge.from).hidden;
                const toVisible = !data.nodes.get(edge.to).hidden;
                data.edges.update({{ id: edge.id, hidden: !(fromVisible && toVisible) }});
            }});
            
            if (nodesToShow.length > 0) {{
                network.fit({{
                    nodes: nodesToShow,
                    animation: {{ duration: 500 }}
                }});
            }}
        }}
        
        // Функция поиска пути (BFS)
        function findPath() {{
            const source = document.getElementById('pathSource').value.trim();
            const target = document.getElementById('pathTarget').value.trim();
            
            if (!source || !target) {{
                alert('Введите источник и назначение');
                return;
            }}
            
            // Проверяем существование узлов
            const sourceNode = data.nodes.get(source);
            const targetNode = data.nodes.get(target);
            
            if (!sourceNode) {{
                alert('Узел-источник не найден: ' + source);
                return;
            }}
            if (!targetNode) {{
                alert('Узел-назначения не найден: ' + target);
                return;
            }}
            
            // BFS для поиска пути
            const pathResult = bfs(source, target);
            
            if (pathResult && pathResult.path.length > 0) {{
                const path = pathResult.path;
                const edgeInfos = pathResult.edges;
                
                // Подсвечиваем узлы пути
                network.selectNodes(path);
                
                // Подсвечиваем рёбра пути с цветами (зеленый/красный)
                const blockedDevices = [];
                const allowedDevices = [];
                
                for (let i = 0; i < path.length - 1; i++) {{
                    const edges = data.edges.get({{
                        filter: edge => edge.from === path[i] && edge.to === path[i+1]
                    }});
                    
                    if (edges.length > 0) {{
                        const edge = edges[0];
                        const edgeInfo = edgeInfos[i];
                        
                        // Определяем цвет на основе правил
                        let newColor = '#666';
                        let newWidth = 1;
                        let deviceInfo = '';
                        
                        if (edgeInfo) {{
                            // Проверяем action правила
                            if (edgeInfo.action === 'deny' || edgeInfo.action === 'drop') {{
                                newColor = '#FF0000';  // Красный - заблокировано
                                newWidth = 5;
                                deviceInfo = edgeInfo.device || path[i];
                                if (!blockedDevices.includes(deviceInfo)) {{
                                    blockedDevices.push(deviceInfo);
                                }}
                            }} else if (edgeInfo.action === 'accept' || edgeInfo.action === 'allow') {{
                                newColor = '#00AA00';  // Зеленый - разрешено
                                newWidth = 4;
                                deviceInfo = edgeInfo.device || path[i];
                                if (!allowedDevices.includes(deviceInfo)) {{
                                    allowedDevices.push(deviceInfo);
                                }}
                            }}
                        }}
                        
                        // Обновляем стиль ребра
                        data.edges.update({{
                            id: edge.id,
                            color: {{ color: newColor }},
                            width: newWidth,
                            title: edge.title + (edgeInfo ? '\\nДействие: ' + edgeInfo.action : '')
                        }});
                    }}
                }}
                
                // Формируем сообщение о пути
                let message = 'Путь: ' + path.join(' → ') + ' (' + (path.length - 1) + ' шагов)';
                
                if (blockedDevices.length > 0) {{
                    message += '\\n⚠️ BLOCKED at: ' + blockedDevices.join(', ');
                }} else if (allowedDevices.length > 0) {{
                    message += '\\n✅ Path fully accessible through: ' + allowedDevices.join(', ');
                }}
                
                showPathMessage(message);
                
                // Центрируем на пути
                network.fit({{
                    nodes: path,
                    animation: {{ duration: 1000, easingFunction: 'easeInOutQuad' }}
                }});
            }} else {{
                showPathMessage('No path found from ' + source + ' to ' + target);
            }}
        }}
        
        // BFS алгоритм
        function bfs(start, end) {{
            const visited = new Set();
            const queue = [[start]];
            const edgeQueue = [[]];
            
            while (queue.length > 0) {{
                const path = queue.shift();
                const edgeInfoPath = edgeQueue.shift();
                const node = path[path.length - 1];
                
                if (node === end) {{
                    return {{ path: path, edges: edgeInfoPath }};
                }}
                
                if (!visited.has(node)) {{
                    visited.add(node);
                    
                    // Находим всех соседей
                    const edges = data.edges.get({{
                        filter: edge => edge.from === node
                    }});
                    
                    for (const edge of edges) {{
                        if (!visited.has(edge.to)) {{
                            const newPath = [...path, edge.to];
                            
                            // Извлекаем информацию о правиле
                            let edgeInfo = null;
                            if (edge.title) {{
                                const actionMatch = edge.title.match(/Действие:\\s*(\\w+)/i);
                                const deviceMatch = edge.title.match(/Device:\\s*([^\\n]+)/);
                                
                                edgeInfo = {{
                                    action: actionMatch ? actionMatch[1].toLowerCase() : 'unknown',
                                    device: deviceMatch ? deviceMatch[1] : null
                                }};
                            }}
                            
                            const newEdgeInfo = [...edgeInfoPath, edgeInfo];
                            queue.push(newPath);
                            edgeQueue.push(newEdgeInfo);
                        }}
                    }}
                }}
            }}
            
            return null;
        }}
        
        function showPathMessage(msg) {{
            const el = document.getElementById('pathMessage');
            el.textContent = msg;
            el.style.display = 'block';
            setTimeout(() => el.style.display = 'none', 5000);
        }}
        
        // Функция фильтрации по подсети
        function filterBySubnet() {{
            const selectedSubnet = document.getElementById('subnetFilter').value;
            
            if (selectedSubnet === 'all') {{
                // Показываем все узлы
                data.nodes.forEach(node => {{
                    data.nodes.update({{ id: node.id, hidden: false }});
                }});
                network.fit();
                return;
            }}
            
            // Фильтруем узлы по подсети
            const nodesToShow = [];
            data.nodes.forEach(node => {{
                if (node.subnet === selectedSubnet) {{
                    nodesToShow.push(node.id);
                    data.nodes.update({{ id: node.id, hidden: false }});
                }} else {{
                    data.nodes.update({{ id: node.id, hidden: true }});
                }}
            }});
            
            // Скрываем рёбра к скрытым узлам
            data.edges.forEach(edge => {{
                const fromVisible = !data.nodes.get(edge.from).hidden;
                const toVisible = !data.nodes.get(edge.to).hidden;
                data.edges.update({{ id: edge.id, hidden: !(fromVisible && toVisible) }});
            }});
            
            if (nodesToShow.length > 0) {{
                network.fit({{
                    nodes: nodesToShow,
                    animation: {{ duration: 500 }}
                }});
            }}
        }}
        function resetFilters() {{
            document.getElementById('zoneFilter').value = 'all';
            document.getElementById('subnetFilter').value = 'all';
            document.getElementById('pathSource').value = '';
            document.getElementById('pathTarget').value = '';
            document.getElementById('showHighRisk').checked = true;
            
            // Показываем все узлы
            data.nodes.forEach(node => {{
                data.nodes.update({{ id: node.id, hidden: false }});
            }});
            
            // Показываем все рёбра
            data.edges.forEach(edge => {{
                data.edges.update({{ id: edge.id, hidden: false }});
            }});
            
            network.unselectAll();
            network.fit();
        }}
        
        // Функция показа/скрытия рисков
        function toggleRiskView() {{
            const showHigh = document.getElementById('showHighRisk').checked;
            
            data.edges.forEach(edge => {{
                const isHighRisk = edge.color === 'red' || edge.color === 'orange';
                if (showHigh) {{
                    // Показываем ТОЛЬКО высокий риск
                    data.edges.update({{ id: edge.id, hidden: !isHighRisk }});
                }} else {{
                    // Показываем ВСЕ рёбра
                    data.edges.update({{ id: edge.id, hidden: false }});
                }}
            }});
        }}
        
        // Функция переключения видимости таблицы
        function toggleRulesTable() {{
            const panel = document.getElementById('sidebar');
            panel.classList.toggle('visible');
        }}
        
        // Функция экспорта графа
        function exportGraph() {{
            const canvas = container.getElementsByTagName('canvas')[0];
            if (canvas) {{
                const link = document.createElement('a');
                link.download = 'firewall_graph.png';
                link.href = canvas.toDataURL('image/png');
                link.click();
            }}
        }}
        
        // Создание таблицы правил
        function createRulesTable() {{
            const tbody = document.getElementById('rulesTableBody');
            if (!tbody) return;
            
            tbody.innerHTML = '';
            
            rulesData.forEach(function(rule, index) {{
                const row = document.createElement('tr');
                
                row.innerHTML = `
                    <td title="${{rule.name}}">${{rule.name}}</td>
                    <td title="${{rule.sources}}">${{rule.sources}}</td>
                    <td title="${{rule.destinations}}">${{rule.destinations}}</td>
                    <td>${{rule.services}}</td>
                    <td><span style="color: ${{rule.action === 'accept' ? 'green' : 'red'}}">${{rule.action}}</span></td>
                `;
                
                // Подсветка при наведении
                row.addEventListener('mouseenter', () => {{
                    row.style.backgroundColor = '#e3f2fd';
                    // Находим и подсвечиваем связанные рёбра
                    const edges = data.edges.get({{
                        filter: edge => edge.title && edge.title.includes(rule.name)
                    }});
                    if (edges.length > 0) {{
                        network.selectEdges(edges.map(e => e.id));
                    }}
                }});
                
                row.addEventListener('mouseleave', () => {{
                    row.style.backgroundColor = '';
                    network.unselectAll();
                }});
                
                tbody.appendChild(row);
            }});
        }}
        
        // Инициализация при загрузке
        document.addEventListener('DOMContentLoaded', function() {{
            createRulesTable();
            
            // Добавляем обработчики событий клика
            network.on('click', function(params) {{
                if (params.nodes.length > 0) {{
                    showNodeInfo(params.nodes[0]);
                }} else if (params.edges.length > 0) {{
                    showEdgeInfo(params.edges[0]);
                }} else {{
                    closeInfoPanel();
                }}
            }});
        }});
        
        // Поиск узла
        function searchNode() {{
            const searchValue = document.getElementById('nodeSearch').value.trim();
            if (!searchValue) return;
            
            // Ищем узел по ID или label
            const foundNode = data.nodes.get(searchValue);
            if (!foundNode) {{
                // Пробуем найти по частичному совпадению
                const nodes = data.nodes.get({{
                    filter: node => node.id.toLowerCase().includes(searchValue.toLowerCase()) || 
                                    (node.label && node.label.toLowerCase().includes(searchValue.toLowerCase()))
                }});
                if (nodes.length > 0) {{
                    // Выбираем первый найденный
                    focusOnNode(nodes[0].id);
                }} else {{
                    alert('Node not found: ' + searchValue);
                }}
            }} else {{
                focusOnNode(foundNode.id);
            }}
        }}
        
        // Фокус на узел
        function focusOnNode(nodeId) {{
            network.selectNodes([nodeId]);
            network.focus(nodeId, {{
                scale: 1.5,
                animation: {{ duration: 500, easingFunction: 'easeInOutQuad' }}
            }});
            showNodeInfo(nodeId);
        }}
        
        // Показать информацию об узле
        function showNodeInfo(nodeId) {{
            const node = data.nodes.get(nodeId);
            if (!node) return;
            
            const panel = document.getElementById('infoPanel');
            const title = document.getElementById('infoPanelTitle');
            const content = document.getElementById('infoPanelContent');
            
            title.textContent = 'Узел: ' + nodeId;
            
            let html = '';
            html += '<div class="info-row"><div class="info-label">Type</div><div class="info-value">' + (node.group || 'Unknown') + '</div></div>';
            if (node.zone) {{
                html += '<div class="info-row"><div class="info-label">Zone</div><div class="info-value">' + node.zone + '</div></div>';
            }}
            if (node.subnet) {{
                html += '<div class="info-row"><div class="info-label">Subnet</div><div class="info-value">' + node.subnet + '</div></div>';
            }}
            if (node.title) {{
                html += '<div class="info-row"><div class="info-label">Details</div><div class="info-value">' + node.title.replace(/\\n/g, '<br>') + '</div></div>';
            }}
            
            // Находим связанные правила
            const connectedEdges = data.edges.get({{
                filter: edge => edge.from === nodeId || edge.to === nodeId
            }});
            if (connectedEdges.length > 0) {{
                html += '<div class="info-row"><div class="info-label">Соединения</div><div class="info-value">' + connectedEdges.length + '</div></div>';
            }}
            
            content.innerHTML = html;
            panel.classList.add('visible');
        }}
        
        // Показать информацию о ребре
        function showEdgeInfo(edgeId) {{
            const edge = data.edges.get(edgeId);
            if (!edge) return;
            
            const panel = document.getElementById('infoPanel');
            const title = document.getElementById('infoPanelTitle');
            const content = document.getElementById('infoPanelContent');
            
            title.textContent = 'Соединение';
            
            let html = '';
            html += '<div class="info-row"><div class="info-label">От</div><div class="info-value">' + edge.from + '</div></div>';
            html += '<div class="info-row"><div class="info-label">До</div><div class="info-value">' + edge.to + '</div></div>';
            if (edge.title) {{
                html += '<div class="info-row"><div class="info-label">Правила</div><div class="info-value">' + edge.title.replace(/\\n/g, '<br>') + '</div></div>';
            }}
            if (edge.risk_score) {{
                html += '<div class="info-row"><div class="info-label">Риск</div><div class="info-value">' + edge.risk_score + '</div></div>';
            }}
            
            content.innerHTML = html;
            panel.classList.add('visible');
        }}
        
        // Закрыть информационную панель
        function closeInfoPanel() {{
            const panel = document.getElementById('infoPanel');
            panel.classList.remove('visible');
        }}
        
        // Переключение темы
        function toggleTheme() {{
            document.body.classList.toggle('dark-theme');
        }}
        
        // Переключение физики
        function togglePhysics() {{
            const enabled = document.getElementById('physicsEnabled').checked;
            network.setOptions({{ physics: {{ enabled: enabled }} }});
        }}
        
        // Смена layout
        function changeLayout() {{
            const layout = document.getElementById('layoutMode').value;
            let newOptions = {{}};
            
            if (layout === 'hierarchical') {{
                newOptions = {{
                    layout: {{
                        hierarchical: {{
                            enabled: true,
                            direction: 'UD',  // Up-Down
                            sortMethod: 'directed',
                            levelSeparation: 150,
                            nodeSpacing: 200
                        }}
                    }},
                    physics: {{
                        enabled: false  // Отключаем физику для иерархии
                    }}
                }};
            }} else if (layout === 'circular') {{
                // Для circular используем forceAtlas2 с центральной гравитацией
                newOptions = {{
                    layout: {{
                        hierarchical: false
                    }},
                    physics: {{
                        enabled: true,
                        forceAtlas2Based: {{
                            gravitationalConstant: -200,
                            centralGravity: 0.1,
                            springLength: 250,
                            springConstant: 0.05,
                            damping: 0.8
                        }},
                        solver: 'forceAtlas2Based'
                    }}
                }};
            }} else {{
                // Standard
                newOptions = {{
                    layout: {{
                        hierarchical: false
                    }},
                    physics: {{
                        enabled: document.getElementById('physicsEnabled').checked,
                        forceAtlas2Based: {{
                            gravitationalConstant: -50,
                            centralGravity: 0.01,
                            springLength: 200,
                            springConstant: 0.08,
                            damping: 0.4
                        }},
                        solver: 'forceAtlas2Based'
                    }}
                }};
            }}
            
            network.setOptions(newOptions);
            network.fit();
        }}
        
        // Переключение режима просмотра
        function switchViewMode() {{
            const mode = document.getElementById('viewMode').value;
            const container = document.getElementById('mynetwork');
            
            if (mode === 'topology') {{
                // Проверяем, есть ли данные топологии
                if (!topologyData || topologyData.nodes.length === 0) {{
                    showPathMessage('⚠️ No topology data available. Parse device configs first.');
                    document.getElementById('viewMode').value = 'access';
                    return;
                }}
                
                // Переключаемся на топологию
                currentViewMode = 'topology';
                
                // Сохраняем текущие данные access graph
                accessGraphNodes = data.nodes.get({{ filter: item => true }});
                accessGraphEdges = data.edges.get({{ filter: item => true }});
                
                // Загружаем данные топологии
                data.nodes.clear();
                data.edges.clear();
                data.nodes.add(topologyData.nodes);
                data.edges.add(topologyData.edges);
                
                // Настройки для топологии
                network.setOptions({{
                    nodes: {{
                        shape: 'box',
                        color: {{
                            background: '#E3F2FD',
                            border: '#1976D2',
                            highlight: {{
                                background: '#BBDEFB',
                                border: '#1565C0'
                            }}
                        }},
                        font: {{ size: 16, bold: true }}
                    }},
                    edges: {{
                        width: 2,
                        color: {{ color: '#424242', opacity: 0.7 }},
                        arrows: {{ to: {{ enabled: true, scaleFactor: 0.8 }} }}
                    }},
                    physics: {{
                        enabled: true,
                        barnesHut: {{
                            gravitationalConstant: -2000,
                            centralGravity: 0.3,
                            springLength: 150,
                            springConstant: 0.04
                        }}
                    }}
                }});
                
                showPathMessage('✓ Switched to Topology view. Showing network topology.');
                
            }} else if (mode === 'access') {{
                // Переключаемся на access graph
                currentViewMode = 'access';
                
                // Восстанавливаем данные access graph
                if (accessGraphNodes && accessGraphNodes.length > 0) {{
                    data.nodes.clear();
                    data.edges.clear();
                    data.nodes.add(accessGraphNodes);
                    data.edges.add(accessGraphEdges);
                }}
                
                // Восстанавливаем настройки
                network.setOptions({{
                    nodes: {{
                        shape: 'dot',
                        color: {{
                            background: '#97C2FC',
                            border: '#2B7CE9',
                            highlight: {{
                                background: '#D2E5FF',
                                border: '#2B7CE9'
                            }}
                        }},
                        font: {{ size: 14 }}
                    }},
                    edges: {{
                        width: 1,
                        color: {{ color: '#848484', opacity: 0.4 }},
                        arrows: {{ to: {{ enabled: true, scaleFactor: 0.5 }} }}
                    }}
                }});
                
                // Применяем выбранный layout
                changeLayout();
                
                showPathMessage('✓ Switched to Access Graph view. Showing firewall rules.');
            }}
        }}
        
        // Глобальные переменные для view mode
        let currentViewMode = 'access';
        let accessGraphNodes = [];
        let accessGraphEdges = [];
        // topologyData уже объявлен выше
        let hierarchicalGroups = {{}};
        let originalNodes = [];
        let hierarchicalMode = false;
        
        // Переключение иерархической группировки IP
        function toggleHierarchicalIp() {{
            hierarchicalMode = document.getElementById('hierarchicalIp').checked;
            
            if (hierarchicalMode) {{
                enableHierarchicalIpGrouping();
            }} else {{
                disableHierarchicalIpGrouping();
            }}
        }}
        
        // Включение иерархической группировки
        function enableHierarchicalIpGrouping() {{
            // Сохраняем оригинальные узлы
            if (originalNodes.length === 0) {{
                originalNodes = data.nodes.get({{ filter: item => true }});
            }}
            
            // Создаём иерархические группы по октетам
            const octetGroups = {{}};
            const hostNodes = [];
            
            originalNodes.forEach(node => {{
                const ip = node.id;
                const octets = parseOctets(ip);
                
                if (octets.length === 4) {{
                    const [o1, o2, o3, o4] = octets;
                    
                    // Создаём группы для каждого уровня
                    const group1Key = `${{o1}}.*.*.*`;
                    const group2Key = `${{o1}}.${{o2}}.*.*`;
                    const group3Key = `${{o1}}.${{o2}}.${{o3}}.*`;
                    
                    if (!octetGroups[group1Key]) {{
                        octetGroups[group1Key] = {{ 
                            id: group1Key, 
                            label: group1Key, 
                            group: 'octet1',
                            level: 1,
                            color: '#E3F2FD',
                            font: {{ size: 16, bold: true }},
                            borderWidth: 3,
                            shape: 'box',
                            margin: 15
                        }};
                    }}
                    if (!octetGroups[group2Key]) {{
                        octetGroups[group2Key] = {{ 
                            id: group2Key, 
                            label: group2Key, 
                            group: 'octet2',
                            level: 2,
                            color: '#BBDEFB',
                            font: {{ size: 14 }},
                            borderWidth: 2,
                            shape: 'box',
                            margin: 12,
                            parent: group1Key
                        }};
                    }}
                    if (!octetGroups[group3Key]) {{
                        octetGroups[group3Key] = {{ 
                            id: group3Key, 
                            label: group3Key, 
                            group: 'octet3',
                            level: 3,
                            color: '#90CAF9',
                            font: {{ size: 12 }},
                            borderWidth: 2,
                            shape: 'box',
                            margin: 10,
                            parent: group2Key
                        }};
                    }}
                    
                    // Создаём хост-узел
                    const hostNode = {{
                        id: ip,
                        label: ip.split('.')[3],
                        group: 'host',
                        level: 4,
                        color: node.color || '#FFB6C1',
                        shape: 'dot',
                        size: 15,
                        parent: group3Key,
                        title: node.title || ip
                    }};
                    hostNodes.push(hostNode);
                }} else {{
                    // Не-IP узлы оставляем как есть
                    hostNodes.push(node);
                }}
            }});
            
            // Обновляем данные
            const allNodes = [...Object.values(octetGroups), ...hostNodes];
            data.nodes.clear();
            data.nodes.add(allNodes);
            
            // Добавляем рёбра между группами
            const groupEdges = [];
            Object.values(octetGroups).forEach(group => {{
                if (group.parent) {{
                    groupEdges.push({{
                        from: group.parent,
                        to: group.id,
                        color: {{ color: '#999', opacity: 0.3 }},
                        width: 1,
                        dashes: true,
                        arrows: {{ to: false }}
                    }});
                }}
            }});
            
            // Добавляем связи от групп к хостам
            hostNodes.forEach(host => {{
                if (host.parent) {{
                    groupEdges.push({{
                        from: host.parent,
                        to: host.id,
                        color: {{ color: '#999', opacity: 0.3 }},
                        width: 1,
                        arrows: {{ to: false }}
                    }});
                }}
            }});
            
            data.edges.clear();
            data.edges.add(groupEdges);
            
            // Включаем иерархическую раскладку
            network.setOptions({{
                layout: {{
                    hierarchical: {{
                        enabled: true,
                        direction: 'UD',
                        sortMethod: 'directed',
                        levelSeparation: 120,
                        nodeSpacing: 180,
                        treeSpacing: 200
                    }}
                }},
                physics: {{ enabled: false }}
            }});
            
            showPathMessage('Hierarchical IP grouping enabled');
        }}
        
        // Выключение иерархической группировки
        function disableHierarchicalIpGrouping() {{
            if (originalNodes.length > 0) {{
                // Восстанавливаем оригинальные узлы
                data.nodes.clear();
                data.nodes.add(originalNodes);
                
                // Восстанавливаем рёбра
                const originalEdges = edgesData.map(e => ({{
                    from: e.from,
                    to: e.to,
                    color: e.color,
                    width: e.width,
                    title: e.title
                }}));
                data.edges.clear();
                data.edges.add(originalEdges);
                
                // Восстанавливаем настройки layout
                changeLayout();
                
                showPathMessage('Hierarchical IP grouping disabled');
            }}
        }}
        
        // Парсинг октетов IP
        function parseOctets(ipString) {{
            const match = ipString.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)/);
            if (match) {{
                return [parseInt(match[1]), parseInt(match[2]), parseInt(match[3]), parseInt(match[4])];
            }}
            return [];
        }}
    </script>
</body>
</html>"""
    
    def _group_nodes_by_subnet(self, nodes_data: List[Dict]) -> List[Dict]:
        """Группирует узлы по подсетям (по третьему октету).
        
        Добавляет к каждому узлу информацию о его подсети для группировки в UI.
        """
        import re
        import ipaddress
        
        grouped_nodes = []
        subnet_groups = {}  # subnet -> group_id
        
        for node in nodes_data:
            node_id = node['id']
            subnet = self._extract_subnet_third_octet(node_id)
            
            # Добавляем информацию о подсети
            node_copy = node.copy()
            node_copy['subnet'] = subnet
            
            # Если это IP или сеть, добавляем группу
            if subnet != 'Other':
                if subnet not in subnet_groups:
                    subnet_groups[subnet] = len(subnet_groups)
                node_copy['group_id'] = f"subnet_{subnet_groups[subnet]}"
            
            grouped_nodes.append(node_copy)
        
        return grouped_nodes
    
    def _extract_subnet_third_octet(self, value: str) -> str:
        """Извлекает подсеть из IP или сетевого адреса (первые 3 октета).
        
        Примеры:
        - 192.168.232.204 -> 192.168.232.0/24
        - 192.168.232.0/24 -> 192.168.232.0/24
        - 192.168.253.0/0.0.0.255 -> 192.168.253.0/24
        """
        import re
        import ipaddress
        
        # Проверяем IP с wildcard mask
        wildcard_match = re.match(r'(\d+\.\d+\.\d+)\.\d+/((?:\d+\.){3}\d+)', value)
        if wildcard_match:
            return wildcard_match.group(1) + '.0/24'
        
        # Проверяем CIDR
        cidr_match = re.match(r'(\d+\.\d+\.\d+)\.\d+/\d+', value)
        if cidr_match:
            return cidr_match.group(1) + '.0/24'
        
        # Проверяем обычный IP
        ip_match = re.match(r'(\d+\.\d+\.\d+)\.\d+$', value)
        if ip_match:
            return ip_match.group(1) + '.0/24'
        
        return 'Other'
    
    def _generate_zone_options(self, nodes_data: List[Dict]) -> str:
        """Генерирует HTML опции для фильтра зон с группировкой по подсетям."""
        
        # Группируем узлы по подсетям
        zones_by_subnet = {}
        other_zones = {}
        
        for node in nodes_data:
            zone = node.get('group', 'Unknown')
            subnet = node.get('subnet', 'Other')
            
            if subnet != 'Other':
                if subnet not in zones_by_subnet:
                    zones_by_subnet[subnet] = {'zones': set(), 'nodes': 0}
                zones_by_subnet[subnet]['zones'].add(zone)
                zones_by_subnet[subnet]['nodes'] += 1
            else:
                if zone not in other_zones:
                    other_zones[zone] = 0
                other_zones[zone] += 1
        
        # Генерируем HTML
        options = []
        
        # Сначала подсети (сортируем для стабильности)
        for subnet in sorted(zones_by_subnet.keys(), key=lambda x: [int(n) for n in x.split('/')[0].split('.')]):
            info = zones_by_subnet[subnet]
            node_count = info['nodes']
            # Используем subnet как value для фильтрации
            options.append(f'<option value="subnet:{subnet}">📁 Subnet {subnet} ({node_count} nodes)</option>')
            # Добавляем зоны внутри подсети как подгруппы
            for zone in sorted(info['zones']):
                options.append(f'<option value="zone:{zone}">   └─ {zone}</option>')
        
        # Затем другие зоны
        for zone in sorted(other_zones.keys()):
            options.append(f'<option value="zone:{zone}">🌐 {zone}</option>')
        
        return ''.join(options)
    
    def _generate_fallback_html(self, output_path: Path, title: str) -> Path:
        """Генерирует базовый HTML без pyvis."""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .node {{ margin: 10px 0; padding: 10px; background: #f0f0f0; border-radius: 5px; }}
        .edge {{ margin: 5px 0; padding: 5px; border-left: 3px solid #666; padding-left: 10px; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <h2>Nodes ({len(self.graph.nodes())})</h2>
    {''.join(f'<div class="node">{node}</div>' for node in self.graph.nodes())}
    <h2>Edges ({len(self.graph.edges())})</h2>
    {''.join(f'<div class="edge">{src} → {dst}</div>' for src, dst in self.graph.edges())}
</body>
</html>"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return output_path
