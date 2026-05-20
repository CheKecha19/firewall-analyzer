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
    
    def _build_agraph(self):
        """Строит pygraphviz AGraph с раскраской узлов и рёбер."""
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
        
        return A
    
    def _draw_matplotlib(self, output_path: Path, fmt: str = 'png') -> Optional[Path]:
        """Рисует граф через matplotlib (fallback)."""
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
        plt.savefig(str(output_path), dpi=150, bbox_inches='tight', facecolor='white', format=fmt)
        plt.close()
        
        return output_path
    
    def generate_png(self, output_path: Path) -> Optional[Path]:
        """Генерирует статическое PNG изображение через Graphviz."""
        try:
            A = self._build_agraph()
            A.draw(str(output_path), prog='dot', format='png')
            return output_path
        except ImportError:
            try:
                return self._draw_matplotlib(output_path, fmt='png')
            except ImportError:
                print("[WARN] pygraphviz or matplotlib not installed. PNG not generated.")
                return None
    
    def generate_pdf(self, output_path: Path) -> Optional[Path]:
        """Генерирует PDF-документ с графом правил через Graphviz."""
        try:
            A = self._build_agraph()
            A.draw(str(output_path), prog='dot', format='pdf')
            return output_path
        except ImportError:
            try:
                return self._draw_matplotlib(output_path, fmt='pdf')
            except ImportError:
                print("[WARN] pygraphviz or matplotlib not installed. PDF not generated.")
                return None
    
    def _hilbert_xy_to_d(self, x: int, y: int, n: int) -> int:
        """Convert 2D (x,y) to distance along Hilbert curve of order n."""
        d = 0
        s = 1 << (n - 1)
        while s > 0:
            rx = 1 if (x & s) > 0 else 0
            ry = 1 if (y & s) > 0 else 0
            d += s * s * ((3 * rx) ^ ry)
            x, y = self._hilbert_rot(s, x, y, rx, ry)
            s >>= 1
        return d

    def _hilbert_rot(self, s: int, x: int, y: int, rx: int, ry: int):
        if ry == 0:
            if rx == 1:
                x = s - 1 - x
                y = s - 1 - y
            x, y = y, x
        return x, y

    def _hilbert_d_to_xy(self, d: int, n: int):
        """Convert distance along Hilbert curve to 2D (x,y) coordinates of order n."""
        x = 0
        y = 0
        t = d
        s = 1
        while s < (1 << n):
            rx = 1 & (t // 2)
            ry = 1 & (t ^ rx)
            x, y = self._hilbert_rot(s, x, y, rx, ry)
            x += s * rx
            y += s * ry
            t //= 4
            s <<= 1
        return x, y

    def _generate_hilbert_data(self) -> dict:
        """
        Generate Hilbert-curve mapping of IP-space for all endpoint nodes with CIDR.
        Returns dict with 'points' list and 'gridSize'.
        """
        import ipaddress
        import re

        order = 12  # 4096x4096 grid
        grid_size = 1 << order
        points = []

        cidr_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d+)?$')

        for node, data in self.graph.nodes(data=True):
            node_str = str(node)
            # Try node name as CIDR/IP first
            match = cidr_pattern.match(node_str)
            if not match:
                # Try data fields
                for key in ('cidr', 'ip', 'network'):
                    val = data.get(key)
                    if val:
                        val_str = str(val)
                        match = cidr_pattern.match(val_str)
                        if match:
                            node_str = val_str
                            break
                if not match:
                    continue

            # Extract first IP from CIDR
            try:
                net = ipaddress.IPv4Network(node_str, strict=False)
                first_ip = int(net.network_address)
            except ValueError:
                continue

            # Take top 24 bits and convert via Hilbert curve to 2D
            hilbert_val = (first_ip >> 8) & (grid_size * grid_size - 1)
            x, y = self._hilbert_d_to_xy(hilbert_val, order)

            zone = data.get('zone', 'Unknown')
            risk_score = data.get('risk_score', 0)

            points.append({
                'ip': str(net.network_address),
                'cidr': node_str,
                'zone': zone,
                'risk_score': risk_score,
                'x': x,
                'y': y,
                'node_name': node_str,
            })

        return {
            'points': points,
            'gridSize': grid_size,
            'totalPoints': len(points),
        }

    def _generate_zone_matrix_data(self) -> dict:
        """
        Собирает данные для матрицы зон безопасности N×N.

        Из NetworkX графа:
        - Собрать все уникальные зоны из node data ('zone')
        - Для каждой пары (src_zone, dst_zone) посчитать:
          - total_rules: количество рёбер
          - accept_rules: сколько с action=accept
          - deny_rules: сколько с action=deny
          - avg_risk: средний risk_score
          - rule_names: список до 5 имён правил (для tooltip)
        """
        # Собираем зоны из узлов
        node_zones = {}
        for node, data in self.graph.nodes(data=True):
            zone = data.get('zone') or 'Unknown'
            node_zones[node] = zone

        # Filter out None values before sorting
        zones = sorted(set(z for z in node_zones.values() if z is not None))
        if not zones:
            return {'zones': [], 'cells': {}}

        # Строим словарь rule_name -> rule для быстрого lookup
        rule_map = {}
        if self.rules:
            for r in self.rules:
                rule_map[r.name] = r

        # Инициализируем cells
        cells = {}
        for sz in zones:
            for dz in zones:
                key = f"{sz}|||{dz}"
                cells[key] = {
                    'total': 0,
                    'accept': 0,
                    'deny': 0,
                    'riskSum': 0,
                    'ruleNames': []
                }

        # Обходим все рёбра
        for src, dst, data in self.graph.edges(data=True):
            src_zone = node_zones.get(src, 'Unknown')
            dst_zone = node_zones.get(dst, 'Unknown')
            key = f"{src_zone}|||{dst_zone}"
            if key not in cells:
                continue

            cell = cells[key]
            cell['total'] += 1

            # Считаем action из имён правил (если есть доступ к rules)
            edge_rules = data.get('rules', [])
            accept_count = 0
            deny_count = 0
            for rname in edge_rules:
                r = rule_map.get(rname)
                if r:
                    action = getattr(r, 'action', '').lower()
                    if action in ('accept', 'allow', 'permit'):
                        accept_count += 1
                    elif action in ('deny', 'drop', 'reject'):
                        deny_count += 1
            cell['accept'] += accept_count
            cell['deny'] += deny_count

            # Risk score (из данных ребра, если есть)
            risk = data.get('risk_score', 0)
            cell['riskSum'] += risk

            # Имена правил (до 5)
            for rname in edge_rules[:5]:
                if rname not in cell['ruleNames']:
                    cell['ruleNames'].append(rname)
                    if len(cell['ruleNames']) >= 5:
                        break

        # Финальная обработка: avg_risk и сортировка ruleNames
        for key, cell in cells.items():
            if cell['total'] > 0:
                cell['avgRisk'] = round(cell['riskSum'] / cell['total'], 1)
            else:
                cell['avgRisk'] = 0
            # Убираем riskSum — не нужен в JSON
            del cell['riskSum']
            cell['ruleNames'] = cell['ruleNames'][:5]

        return {'zones': zones, 'cells': cells}

    def _generate_sankey_data(self) -> dict:
        """Собирает данные для Sankey-диаграммы: source_zone → dest_zone."""
        flows = {}  # (source_zone, dest_zone) -> {count, risk_sum}
        zone_set = set()
        
        for src, dst, data in self.graph.edges(data=True):
            src_zone = self.graph.nodes[src].get('zone', 'Unknown') or 'Unknown'
            dst_zone = self.graph.nodes[dst].get('zone', 'Unknown') or 'Unknown'
            risk = data.get('risk_score', 0)
            
            key = (src_zone, dst_zone)
            if key not in flows:
                flows[key] = {'count': 0, 'risk_sum': 0}
            flows[key]['count'] += 1
            flows[key]['risk_sum'] += risk
            zone_set.add(src_zone)
            zone_set.add(dst_zone)
        
        # Список уникальных зон как узлы Sankey
        nodes = sorted(zone_set)
        node_index = {name: i for i, name in enumerate(nodes)}
        
        # Формируем потоки
        links = []
        for (src_z, dst_z), v in flows.items():
            if v['count'] > 0:
                links.append({
                    'source': node_index[src_z],
                    'target': node_index[dst_z],
                    'value': v['count'],
                    'avgRisk': round(v['risk_sum'] / v['count'], 1),
                    'srcZone': src_z,
                    'dstZone': dst_z
                })
        
        return {'nodes': nodes, 'links': links}
    
    def _generate_service_data(self) -> list:
        """
        Собирает статистику использования сервисов из рёбер графа.
        Возвращает топ-30 сервисов: [{name, count, protocol, percentage}]
        """
        from collections import Counter

        # Build service -> protocol lookup from rules
        svc_protocol = {}
        if self.rules:
            for r in self.rules:
                for s in r.services:
                    svc_protocol[s.name] = s.protocol

        # Count service usage across all edges
        svc_counter = Counter()
        total_usages = 0
        for _src, _dst, data in self.graph.edges(data=True):
            edge_services = data.get('services', [])
            for svc_name in edge_services:
                svc_counter[svc_name] += 1
                total_usages += 1

        if not svc_counter:
            return []

        # Top 30
        top = svc_counter.most_common(30)
        result = []
        for name, count in top:
            pct = round(count / total_usages * 100, 1) if total_usages > 0 else 0
            result.append({
                'name': name,
                'count': count,
                'protocol': svc_protocol.get(name, 'ip'),
                'percentage': pct
            })
        return result

    def _generate_risk_severity_data(self) -> list:
        """
        Группирует рёбра графа по severity на основе risk_score.
        Возвращает: [{severity, count, percentage, color}]
        """
        buckets = {
            'low': {'min': 0, 'max': 2, 'count': 0, 'color': '#00FF00'},
            'medium-low': {'min': 3, 'max': 4, 'count': 0, 'color': '#90EE90'},
            'medium': {'min': 5, 'max': 6, 'count': 0, 'color': '#FFD700'},
            'high': {'min': 7, 'max': 8, 'count': 0, 'color': '#FF8C00'},
            'critical': {'min': 9, 'max': 10, 'count': 0, 'color': '#FF0000'},
        }

        total = 0
        for _src, _dst, data in self.graph.edges(data=True):
            rs = data.get('risk_score', 0)
            for info in buckets.values():
                if info['min'] <= rs <= info['max']:
                    info['count'] += 1
                    total += 1
                    break

        result = []
        for severity, info in buckets.items():
            pct = round(info['count'] / total * 100, 1) if total > 0 else 0
            result.append({
                'severity': severity,
                'count': info['count'],
                'percentage': pct,
                'color': info['color']
            })
        return result

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
                    'title': edge_title,
                    'riskScore': risk
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
            
            # Данные для Sankey
            sankey_data = self._generate_sankey_data()

            # Данные для Zone Matrix
            zone_matrix_data = self._generate_zone_matrix_data()

            # Данные для Service Treemap
            service_data = self._generate_service_data()

            # Данные для Risk Severity Donut
            risk_severity_data = self._generate_risk_severity_data()

            # Данные для Hilbert IP-space map
            hilbert_data = self._generate_hilbert_data()

            # Генерируем полный HTML
            html_content = self._generate_full_html(
                title, nodes_data, edges_data, rules_table, topology_data=topology_data,
                sankey_data=sankey_data, zone_matrix_data=zone_matrix_data,
                service_data=service_data, risk_severity_data=risk_severity_data,
                hilbert_data=hilbert_data
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
                           topology_data: Optional[Tuple[List[Dict], List[Dict]]] = None,
                           sankey_data: Optional[dict] = None,
                           zone_matrix_data: Optional[dict] = None,
                           service_data: Optional[list] = None,
                           risk_severity_data: Optional[list] = None,
                           hilbert_data: Optional[dict] = None) -> str:
        """Генерирует полный HTML с встроенным vis-network."""
        
        nodes_json = json.dumps(nodes_data, ensure_ascii=False)
        edges_json = json.dumps(edges_data, ensure_ascii=False)
        rules_json = json.dumps(rules_table, ensure_ascii=False)
        
        # Подготавливаем данные топологии (если есть)
        if topology_data:
            topo_nodes_json = json.dumps(topology_data[0], ensure_ascii=False)
            topo_edges_json = json.dumps(topology_data[1], ensure_ascii=False)
        else:
            topo_nodes_json = '[]'
            topo_edges_json = '[]'
        
        # Данные Sankey
        sankey_json = json.dumps(sankey_data, ensure_ascii=False) if sankey_data else '{"nodes":[],"links":[]}'

        # Данные Zone Matrix
        zone_matrix_json = json.dumps(zone_matrix_data, ensure_ascii=False) if zone_matrix_data else '{"zones":[],"cells":{}}'

        # Данные для Service Treemap
        service_json = json.dumps(service_data, ensure_ascii=False) if service_data else '[]'

        # Данные для Risk Severity Donut
        risk_severity_json = json.dumps(risk_severity_data, ensure_ascii=False) if risk_severity_data else '[]'

        # Данные для Hilbert IP-space map
        hilbert_json = json.dumps(hilbert_data, ensure_ascii=False) if hilbert_data else '{"points":[],"gridSize":4096,"totalPoints":0}'
        
        # Генерируем опции зон
        zones_options = self._generate_zone_options(nodes_data)
        
        # Собираем список всех узлов для автокомплита
        all_nodes = [n['id'] for n in nodes_data]
        nodes_list_json = json.dumps(all_nodes, ensure_ascii=False)
        
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/d3-sankey@0.12.3/dist/d3-sankey.min.js"></script>
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
        
        /* Tab bar */
        #tabBar {{
            display: flex;
            background: white;
            border-bottom: 2px solid #667eea;
            padding: 0 25px;
        }}
        #tabBar .tab {{
            padding: 12px 20px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            color: #666;
            border-bottom: 3px solid transparent;
            transition: all 0.2s;
            user-select: none;
        }}
        #tabBar .tab:hover {{ color: #667eea; background: #f5f5f5; }}
        #tabBar .tab.active {{
            color: #667eea;
            border-bottom-color: #667eea;
            font-weight: 700;
        }}
        
        /* Sankey view */
        #sankeyView {{
            flex: 1;
            background: white;
            border: 1px solid #ddd;
            display: none;
            overflow: hidden;
        }}
        #sankeyView .node rect {{
            fill-opacity: 0.9;
            stroke: #333;
            stroke-width: 1px;
        }}
        #sankeyView .node text {{
            font-size: 12px;
            font-family: 'Segoe UI', sans-serif;
        }}
        #sankeyView .link {{
            fill: none;
            stroke-opacity: 0.4;
            transition: stroke-opacity 0.2s;
        }}
        #sankeyView .link:hover {{ stroke-opacity: 0.8; }}
        
        /* Sankey tooltip */
        #sankeyTooltip {{
            position: fixed;
            background: rgba(0,0,0,0.85);
            color: #fff;
            padding: 10px 14px;
            border-radius: 6px;
            font-size: 12px;
            pointer-events: none;
            z-index: 1000;
            display: none;
            max-width: 250px;
        }}
        
        /* View placeholder */
        .view-placeholder {{
            flex: 1;
            display: none;
            align-items: center;
            justify-content: center;
            background: white;
            border: 1px solid #ddd;
            font-size: 18px;
            color: #999;
        }}

        /* View container (for matrix) */
        .view-container {{
            flex: 1;
            display: none;
            background: white;
            border: 1px solid #ddd;
        }}
        
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
        body.dark-theme #tabBar {{
            background: #16213e;
            border-bottom-color: #0f3460;
        }}
        body.dark-theme #tabBar .tab {{
            color: #aaa;
        }}
        body.dark-theme #tabBar .tab:hover {{
            color: #eee;
            background: #1a1a2e;
        }}
        body.dark-theme #tabBar .tab.active {{
            color: #667eea;
            border-bottom-color: #667eea;
        }}
        body.dark-theme #sankeyView {{
            background: #1a1a2e;
            border-color: #0f3460;
        }}
        body.dark-theme #sankeyView .node text {{
            fill: #ddd;
        }}
        body.dark-theme #matrixView {{
            background: #1a1a2e;
            border-color: #0f3460;
        }}
        body.dark-theme #matrixView table {{
            color: #ddd;
        }}
        body.dark-theme .view-placeholder {{
            background: #1a1a2e;
            border-color: #0f3460;
            color: #888;
        }}
        body.dark-theme .view-container {{
            background: #1a1a2e;
            border-color: #0f3460;
        }}
    </style>
</head>
<body>
    <div id="header">
        <h1>{title}</h1>
        <p>Интерактивная карта сетевого доступа | Наведите на узлы для деталей</p>
    </div>
    
    <div id="tabBar">
        <div class="tab active" data-view="graph" onclick="switchView('graph')">Граф</div>
        <div class="tab" data-view="sankey" onclick="switchView('sankey')">Потоки</div>
        <div class="tab" data-view="matrix" onclick="switchView('matrix')">Матрица</div>
        <div class="tab" data-view="services" onclick="switchView('services')">Сервисы</div>
        <div class="tab" data-view="risks" onclick="switchView('risks')">Риски</div>
        <div class="tab" data-view="hilbert" onclick="switchView('hilbert')">🗺️ Hilbert</div>
    </div>
    
    <div id="controls">
        <div>
            <label>Поиск узла:</label>
            <input type="text" id="nodeSearch" list="nodesList" placeholder="Введите имя узла..." oninput="searchNodeDebounced()">
        </div>
        
        <div>
            <label>Фильтр по зоне:</label>
            <select id="zone-filter" onchange="filterByZone()">
                <option value="all">📋 Все зоны</option>
                {zones_options}
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
            </select>
        </div>
        
        <div>
            <label>Уровень риска: <span id="riskValue">0-10</span></label>
            <div style="display:flex; gap:10px; align-items:center;">
                <input type="range" id="riskMin" min="0" max="10" value="0" style="width:80px" oninput="updateRiskFilter()">
                <span>—</span>
                <input type="range" id="riskMax" min="0" max="10" value="10" style="width:80px" oninput="updateRiskFilter()">
            </div>
        </div>
        
        <button onclick="resetFilters()" class="secondary">Сбросить</button>
        <button onclick="toggleRulesTable()">Таблица правил</button>
        <button onclick="exportGraph()">Экспорт PNG</button>
        <button onclick="toggleTheme()" class="secondary">🌓 Тема</button>
    </div>
    
    <div id="pathMessage"></div>
    
    <div id="main-container">
        <div id="mynetwork"></div>
        <div id="sankeyView"></div>
        <div id="matrixView" class="view-container" style="display:none">
          <div id="matrixContainer" style="width:100%; height:100%; overflow:auto; padding:20px;"></div>
        </div>
        <div id="servicesView" class="view-container" style="display:none">
          <div id="servicesTreemap" style="width:100%; height:100%; overflow:hidden;"></div>
        </div>
        <div id="risksView" class="view-container" style="display:none">
          <div id="risksDonut" style="width:100%; height:100%; overflow:hidden; display:flex; align-items:center; justify-content:center;"></div>
        </div>
        <div id="hilbertView" class="view-container" style="display:none">
          <canvas id="hilbertCanvas" width="600" height="600" style="display:block;margin:0 auto;cursor:grab;"></canvas>
        </div>
        
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
    
    <!-- Sankey tooltip -->
    <div id="sankeyTooltip"></div>
    
    <script type="text/javascript">
        // Данные графа
        var nodesData = {nodes_json};
        var edgesData = {edges_json};
        var rulesData = {rules_json};
        var allNodes = {nodes_list_json};
        var allEdges = edgesData;
        var sankeyData = {sankey_json};
        var zoneMatrixData = {zone_matrix_json};
        var serviceData = {service_json};
        var riskSeverityData = {risk_severity_json};
        var hilbertData = {hilbert_json};
        var nodeCount = nodesData.length;
        
        // Global state
        var network = null;
        var pathData = [];
        var pathAnimationTimer = null;
        var prevGraphState = null;
        var data = null;
        
        function initNetwork() {{
            // Создаём сеть
            var container = document.getElementById('mynetwork');
            data = {{
                nodes: new vis.DataSet(nodesData),
                edges: new vis.DataSet(edgesData)
            }};
            
            // Physics: включаем только если узлов < 50
            var options = {{
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
                    enabled: nodeCount < 50,
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
            
            network = new vis.Network(container, data, options);
            
            // Tab click handlers
            document.querySelectorAll('#tabBar .tab').forEach(function(t) {{
                t.addEventListener('click', function() {{
                    switchView(t.dataset.view);
                }});
            }});
            
            // Network event handlers
            network.on('click', function(params) {{
                if (params.nodes.length > 0) {{
                    showNodeInfo(params.nodes[0]);
                }} else if (params.edges.length > 0) {{
                    showEdgeInfo(params.edges[0]);
                }} else {{
                    closeInfoPanel();
                }}
            }});
            
            // Initialize rules table
            createRulesTable();
        }}
        
        // ===== applyFilters (wrapper for check script) =====
        function applyFilters() {{
            filterByZone();
            updateRiskFilter();
        }}
        
        // ===== View Switching =====
        var currentView = 'graph';
        var sankeyRendered = false;
        var matrixRendered = false;
        var servicesRendered = false;
        var risksRendered = false;
        
        function switchView(view) {{
            if (currentView === view) return;
            currentView = view;
            
            // Обновить табы
            document.querySelectorAll('#tabBar .tab').forEach(t => {{
                t.classList.toggle('active', t.dataset.view === view);
            }});
            
            // Спрятать все view-контейнеры
            document.getElementById('mynetwork').style.display = 'none';
            document.getElementById('sankeyView').style.display = 'none';
            document.getElementById('matrixView').style.display = 'none';
            document.getElementById('servicesView').style.display = 'none';
            document.getElementById('risksView').style.display = 'none';
            
            // Показать активный
            if (view === 'graph') {{
                document.getElementById('mynetwork').style.display = '';
                network.fit();
            }} else if (view === 'sankey') {{
                document.getElementById('sankeyView').style.display = '';
                if (!sankeyRendered) {{
                    renderSankey();
                    sankeyRendered = true;
                }}
            }} else if (view === 'matrix') {{
                document.getElementById('matrixView').style.display = 'block';
                if (!matrixRendered) {{
                    renderMatrix();
                    matrixRendered = true;
                }}
            }} else if (view === 'services') {{
                document.getElementById('servicesView').style.display = 'block';
                if (!servicesRendered) {{
                    renderServiceTreemap();
                    servicesRendered = true;
                }}
            }} else if (view === 'risks') {{
                document.getElementById('risksView').style.display = 'block';
                if (!risksRendered) {{
                    renderRiskDonut();
                    risksRendered = true;
                }}
            }}
        }}

        // ===== Zone Security Matrix =====
        function renderMatrix() {{
            var container = document.getElementById('matrixContainer');
            if (!zoneMatrixData || !zoneMatrixData.zones || zoneMatrixData.zones.length === 0) {{
                container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#999;font-size:16px;">Нет данных о зонах</div>';
                return;
            }}

            var zones = zoneMatrixData.zones;
            var cells = zoneMatrixData.cells;
            var isDark = document.body.classList.contains('dark-theme');

            var bgColor = isDark ? '#16213e' : '#fff';
            var textColor = isDark ? '#ddd' : '#333';
            var headerBg = isDark ? '#0f3460' : '#667eea';
            var headerColor = '#fff';
            var borderColor = isDark ? '#0f3460' : '#ddd';

            var html = '<table style="border-collapse:collapse;font-size:11px;font-family:Segoe UI,sans-serif;">';
            html += '<thead><tr><th style="background:' + headerBg + ';color:' + headerColor + ';padding:6px 8px;position:sticky;top:0;z-index:2;">Src \\ Dst</th>';
            for (var i = 0; i < zones.length; i++) {{
                html += '<th style="background:' + headerBg + ';color:' + headerColor + ';padding:6px 8px;position:sticky;top:0;z-index:2;min-width:90px;text-align:center;">' + zones[i] + '</th>';
            }}
            html += '</tr></thead><tbody>';

            for (var ri = 0; ri < zones.length; ri++) {{
                var srcZone = zones[ri];
                html += '<tr><th style="background:' + headerBg + ';color:' + headerColor + ';padding:6px 8px;position:sticky;left:0;z-index:1;text-align:right;">' + srcZone + '</th>';
                for (var ci = 0; ci < zones.length; ci++) {{
                    var dstZone = zones[ci];
                    var key = srcZone + '|||' + dstZone;
                    var cell = cells[key];
                    var isDiagonal = (srcZone === dstZone);

                    var cellBg = bgColor;
                    var cellText = '';
                    var tooltipText = '';

                    if (cell && cell.total > 0) {{
                        var avgRisk = cell.avgRisk || 0;
                        // Цвет по avg_risk: 0-3 зелёный, 4-6 жёлтый, 7-10 красный
                        if (!isDiagonal) {{
                            if (avgRisk >= 7) cellBg = 'rgba(255,68,68,0.25)';
                            else if (avgRisk >= 4) cellBg = 'rgba(255,204,0,0.25)';
                            else cellBg = 'rgba(39,174,96,0.25)';
                        }}

                        cellText = '<b>' + cell.total + '</b><br><span style="font-size:9px;">' +
                            '<span style="color:#27ae60;">✓' + cell.accept + '</span> ' +
                            '<span style="color:#e74c3c;">✗' + cell.deny + '</span></span>';

                        tooltipText = 'Из <b>' + srcZone + '</b> в <b>' + dstZone + '</b><br>' +
                            'Всего правил: ' + cell.total + '<br>' +
                            'Accept: ' + cell.accept + '<br>' +
                            'Deny: ' + cell.deny + '<br>' +
                            'Avg Risk: ' + (cell.avgRisk || 0);
                        if (cell.ruleNames && cell.ruleNames.length > 0) {{
                            tooltipText += '<br>Правила: ' + cell.ruleNames.join(', ');
                        }}
                    }}

                    if (isDiagonal) {{
                        cellBg = isDark ? '#1a1a2e' : '#f0f0f0';
                        cellText = '<span style="color:#999;font-size:10px;">intra-zone</span>';
                        tooltipText = 'Внутри зоны <b>' + srcZone + '</b>';
                    }}

                    html += '<td style="border:1px solid ' + borderColor + ';padding:6px;text-align:center;' +
                        'cursor:pointer;background:' + cellBg + ';color:' + textColor + ';' +
                        'min-width:90px;transition:background 0.15s;' +
                        '" onmouseover="this.style.filter=\'brightness(1.2)\';" onmouseout="this.style.filter=\'\';"' +
                        ' title="' + tooltipText.replace(/"/g, '&quot;') + '"' +
                        ' onclick="showZoneCellDetail(\'' + srcZone + '\', \'' + dstZone + '\')">' +
                        cellText + '</td>';
                }}
                html += '</tr>';
            }}
            html += '</tbody></table>';
            container.innerHTML = html;
        }}

        function showZoneCellDetail(srcZone, dstZone) {{
            var key = srcZone + '|||' + dstZone;
            var cell = zoneMatrixData.cells[key];
            var isDiagonal = (srcZone === dstZone);

            if (isDiagonal) {{
                alert('Внутризонный трафик: ' + srcZone + '\\nВнутризоновые правила не отображаются в матрице межзоновых политик.');
                return;
            }}

            if (!cell || cell.total === 0) {{
                alert('Нет правил из "' + srcZone + '" в "' + dstZone + '"');
                return;
            }}

            var msg = 'Политика: ' + srcZone + ' → ' + dstZone + '\\n' +
                '━━━━━━━━━━━━━━━━\\n' +
                'Всего правил: ' + cell.total + '\\n' +
                'Accept: ' + cell.accept + '\\n' +
                'Deny: ' + cell.deny + '\\n' +
                'Avg Risk: ' + (cell.avgRisk || 0) + '/10';
            if (cell.ruleNames && cell.ruleNames.length > 0) {{
                msg += '\\n\\nПравила:\\n' + cell.ruleNames.join('\\n');
            }}
            alert(msg);
        }}

        // ===== Sankey Diagram =====
        function riskColor(avgRisk) {{
            if (avgRisk >= 7) return '#e74c3c';   // красный
            if (avgRisk >= 4) return '#f39c12';   // жёлтый
            return '#27ae60';                      // зелёный
        }}
        
        function renderSankey() {{
            const container = document.getElementById('sankeyView');
            if (!sankeyData || !sankeyData.nodes || sankeyData.nodes.length === 0) {{
                container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#999;font-size:16px;">Нет данных о потоках</div>';
                return;
            }}
            
            container.innerHTML = '';
            const width = container.clientWidth || 800;
            const height = container.clientHeight || 500;
            
            const svg = d3.select('#sankeyView').append('svg')
                .attr('width', width)
                .attr('height', height);
            
            const sankeyGenerator = d3.sankey()
                .nodeWidth(24)
                .nodePadding(20)
                .extent([[20, 20], [width - 20, height - 20]]);
            
            const {{nodes, links}} = sankeyGenerator({{
                nodes: sankeyData.nodes.map(d => ({{...d}})),
                links: sankeyData.links.map(d => ({{...d}}))
            }});
            
            // Цветовая шкала для узлов
            const nodeColor = d3.scaleOrdinal(d3.schemeCategory10);
            
            // Рисуем линки
            const link = svg.append('g')
                .attr('fill', 'none')
                .selectAll('path')
                .data(links)
                .join('path')
                .attr('class', 'link')
                .attr('d', d3.sankeyLinkHorizontal())
                .attr('stroke', d => riskColor(d.avgRisk))
                .attr('stroke-width', d => Math.max(1, d.width))
                .on('mouseover', function(event, d) {{
                    d3.select(this).attr('stroke-opacity', 0.8);
                    const tooltip = document.getElementById('sankeyTooltip');
                    tooltip.style.display = 'block';
                    tooltip.innerHTML = `<b>${{d.srcZone}} → ${{d.dstZone}}</b><br>Правил: ${{d.value}}<br>Средний риск: ${{d.avgRisk}}`;
                }})
                .on('mousemove', function(event) {{
                    const tooltip = document.getElementById('sankeyTooltip');
                    tooltip.style.left = (event.pageX + 12) + 'px';
                    tooltip.style.top = (event.pageY - 10) + 'px';
                }})
                .on('mouseout', function() {{
                    d3.select(this).attr('stroke-opacity', 0.4);
                    document.getElementById('sankeyTooltip').style.display = 'none';
                }});
            
            // Рисуем узлы
            const node = svg.append('g')
                .selectAll('g')
                .data(nodes)
                .join('g')
                .attr('class', 'node')
                .attr('transform', d => `translate(${{d.x0}},${{d.y0}})`);
            
            node.append('rect')
                .attr('height', d => d.y1 - d.y0)
                .attr('width', d => d.x1 - d.x0)
                .attr('fill', d => nodeColor(d.name))
                .attr('rx', 2)
                .append('title')
                .text(d => d.name);
            
            node.append('text')
                .attr('x', d => (d.x0 < width / 2) ? 6 + (d.x1 - d.x0) : -6)
                .attr('y', d => (d.y1 - d.y0) / 2)
                .attr('dy', '0.35em')
                .attr('text-anchor', d => (d.x0 < width / 2) ? 'start' : 'end')
                .text(d => d.name)
                .attr('fill', document.body.classList.contains('dark-theme') ? '#ddd' : '#333');
            
            // Handle resize
            window.addEventListener('resize', () => {{
                if (currentView === 'sankey' && sankeyRendered) {{
                    sankeyRendered = false;
                    renderSankey();
                    sankeyRendered = true;
                }}
            }});
        }}
        
        // Debounce для поиска узла
        let searchDebounceTimer = null;
        function searchNodeDebounced() {{
            clearTimeout(searchDebounceTimer);
            searchDebounceTimer = setTimeout(() => searchNode(), 300);
        }}
        
        // Поиск узла
        function searchNode() {{
            const searchValue = document.getElementById('nodeSearch').value.trim();
            if (!searchValue) return;
            
            const foundNode = data.nodes.get(searchValue);
            if (!foundNode) {{
                const nodes = data.nodes.get({{
                    filter: node => node.id.toLowerCase().includes(searchValue.toLowerCase()) || 
                                    (node.label && node.label.toLowerCase().includes(searchValue.toLowerCase()))
                }});
                if (nodes.length > 0) {{
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
        
        // Функция фильтрации по зоне
        function filterByZone() {{
            const selectedValue = document.getElementById('zoneFilter').value;
            
            if (selectedValue === 'all') {{
                data.nodes.forEach(node => {{
                    data.nodes.update({{ id: node.id, hidden: false }});
                }});
                data.edges.forEach(edge => {{
                    data.edges.update({{ id: edge.id, hidden: false }});
                }});
                network.fit();
                return;
            }}
            
            const nodesToShow = [];
            data.nodes.forEach(node => {{
                if (node.group === selectedValue) {{
                    nodesToShow.push(node.id);
                    data.nodes.update({{ id: node.id, hidden: false }});
                }} else {{
                    data.nodes.update({{ id: node.id, hidden: true }});
                }}
            }});
            
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
        
        // Смена layout
        function changeLayout() {{
            const layout = document.getElementById('layoutMode').value;
            let newOptions = {{}};
            
            if (layout === 'hierarchical') {{
                newOptions = {{
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
                }};
            }} else {{
                // Standard
                newOptions = {{
                    layout: {{
                        hierarchical: false
                    }},
                    physics: {{
                        enabled: nodeCount < 50,
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
        
        // ===== Path Trace =====
        function tracePath() {{
            var source = document.getElementById('pathSource').value.trim();
            var target = document.getElementById('pathTarget').value.trim();
            findPath(source, target);
        }}
        
        function clearPath() {{
            // Reset edge colors and widths
            edgesData.forEach(function(e) {{
                var riskVal = e.riskScore != null ? e.riskScore : 0;
                if (riskVal >= 8) {{
                    data.edges.update({{ id: e.id || (e.from + '_' + e.to), color: 'red', width: 4 }});
                }} else if (riskVal >= 5) {{
                    data.edges.update({{ id: e.id || (e.from + '_' + e.to), color: 'orange', width: 2 }});
                }} else {{
                    data.edges.update({{ id: e.id || (e.from + '_' + e.to), color: '#666666', width: 1 }});
                }}
            }});
            pathData = [];
            document.getElementById('pathMessage').style.display = 'none';
            document.getElementById('pathSource').value = '';
            document.getElementById('pathTarget').value = '';
            network.unselectAll();
            network.fit();
        }}
        
        // Функция поиска пути (BFS)
        function findPath(source, target) {{
            if (!source || !target) {{
                alert('Введите источник и назначение');
                return;
            }}
            
            clearPath();
            
            var sourceNode = data.nodes.get(source);
            var targetNode = data.nodes.get(target);
            
            if (!sourceNode) {{
                alert('Узел-источник не найден: ' + source);
                return;
            }}
            if (!targetNode) {{
                alert('Узел-назначения не найден: ' + target);
                return;
            }}
            
            var pathResult = bfs(source, target);
            
            if (pathResult && pathResult.path.length > 0) {{
                var path = pathResult.path;
                var edgeInfos = pathResult.edges;
                
                network.selectNodes(path);
                
                var blockedDevices = [];
                var allowedDevices = [];
                
                for (var i = 0; i < path.length - 1; i++) {{
                    var edges = data.edges.get({{
                        filter: function(edge) {{ return edge.from === path[i] && edge.to === path[i+1]; }}
                    }});
                    
                    if (edges.length > 0) {{
                        var edge = edges[0];
                        var edgeInfo = edgeInfos[i];
                        
                        var newColor = '#666';
                        var newWidth = 1;
                        var deviceInfo = '';
                        
                        if (edgeInfo) {{
                            if (edgeInfo.action === 'deny' || edgeInfo.action === 'drop') {{
                                newColor = '#FF0000';
                                newWidth = 5;
                                deviceInfo = edgeInfo.device || path[i];
                                if (blockedDevices.indexOf(deviceInfo) < 0) {{
                                    blockedDevices.push(deviceInfo);
                                }}
                            }} else if (edgeInfo.action === 'accept' || edgeInfo.action === 'allow') {{
                                newColor = '#00AA00';
                                newWidth = 4;
                                deviceInfo = edgeInfo.device || path[i];
                                if (allowedDevices.indexOf(deviceInfo) < 0) {{
                                    allowedDevices.push(deviceInfo);
                                }}
                            }}
                        }}
                        
                        data.edges.update({{
                            id: edge.id,
                            color: {{ color: newColor }},
                            width: newWidth,
                            title: edge.title + (edgeInfo ? '\nДействие: ' + edgeInfo.action : '')
                        }});
                    }}
                }}
                
                var message = 'Путь: ' + path.join(' → ') + ' (' + (path.length - 1) + ' шагов)';
                
                if (blockedDevices.length > 0) {{
                    message += '\n⚠️ BLOCKED at: ' + blockedDevices.join(', ');
                }} else if (allowedDevices.length > 0) {{
                    message += '\n✅ Path fully accessible through: ' + allowedDevices.join(', ');
                }}
                
                showPathMessage(message);
                
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
                    
                    var edges = data.edges.get({{
                        filter: edge => edge.from === node
                    }});
                    
                    for (const edge of edges) {{
                        if (!visited.has(edge.to)) {{
                            const newPath = [...path, edge.to];
                            
                            let edgeInfo = null;
                            if (edge.title) {{
                                const actionMatch = edge.title.match(/Действие:\\s*(\\w+)/i);
                                const deviceMatch = edge.title.match(/Device:\\s*([^\n]+)/);
                                
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
        
        // Фильтр рёбер по диапазону risk_score (Tufte principle: data stays visible)
        function updateRiskFilter() {{
            const riskMin = parseInt(document.getElementById('riskMin').value);
            const riskMax = parseInt(document.getElementById('riskMax').value);
            document.getElementById('riskValue').textContent = riskMin + '-' + riskMax;
            
            data.edges.forEach(edge => {{
                const risk = edge.riskScore != null ? edge.riskScore : 0;
                if (risk >= riskMin && risk <= riskMax) {{
                    data.edges.update({{ id: edge.id, opacity: 1.0 }});
                }} else {{
                    data.edges.update({{ id: edge.id, opacity: 0.1 }});
                }}
            }});
        }}
        
        function resetFilters() {{
            document.getElementById('zoneFilter').value = 'all';
            document.getElementById('nodeSearch').value = '';
            document.getElementById('pathSource').value = '';
            document.getElementById('pathTarget').value = '';
            document.getElementById('riskMin').value = 0;
            document.getElementById('riskMax').value = 10;
            document.getElementById('riskValue').textContent = '0-10';
            
            data.nodes.forEach(node => {{
                data.nodes.update({{ id: node.id, hidden: false }});
            }});
            
            data.edges.forEach(edge => {{
                data.edges.update({{ id: edge.id, hidden: false, opacity: 1.0 }});
            }});
            
            network.unselectAll();
            network.fit();
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
                
                row.addEventListener('mouseenter', () => {{
                    row.style.backgroundColor = '#e3f2fd';
                    var edges = data.edges.get({{
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
            initNetwork();
        }});
        
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
            if (node.title) {{
                html += '<div class="info-row"><div class="info-label">Details</div><div class="info-value">' + node.title.replace(/\n/g, '<br>') + '</div></div>';
            }}
            
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
                html += '<div class="info-row"><div class="info-label">Правила</div><div class="info-value">' + edge.title.replace(/\n/g, '<br>') + '</div></div>';
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
        
        // ===== Service Treemap (D3.js) =====
        function renderServiceTreemap() {{
            const container = document.getElementById('servicesTreemap');
            if (!serviceData || serviceData.length === 0) {{
                container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#999;font-size:16px;">Нет данных о сервисах</div>';
                return;
            }}
            
            container.innerHTML = '';
            const width = container.clientWidth || 800;
            const height = container.clientHeight || 500;

            // Color by protocol
            const protoColors = {{
                'tcp': '#5B9BD5',
                'udp': '#70AD47',
                'icmp': '#ED7D31',
                'ip': '#A5A5A5'
            }};

            const root = d3.hierarchy({{children: serviceData}})
                .sum(d => d.count)
                .sort((a, b) => b.value - a.value);

            const treemap = d3.treemap()
                .size([width, height])
                .paddingOuter(4)
                .paddingInner(2)
                .round(true);
            treemap(root);

            const svg = d3.select('#servicesTreemap').append('svg')
                .attr('width', width)
                .attr('height', height);

            const cells = svg.selectAll('g')
                .data(root.leaves())
                .join('g')
                .attr('transform', d => `translate(${{d.x0}},${{d.y0}})`);

            const isDark = document.body.classList.contains('dark-theme');
            const textColor = isDark ? '#eee' : '#333';

            cells.append('rect')
                .attr('width', d => Math.max(0, d.x1 - d.x0))
                .attr('height', d => Math.max(0, d.y1 - d.y0))
                .attr('fill', d => protoColors[d.data.protocol] || '#A5A5A5')
                .attr('stroke', '#fff')
                .attr('stroke-width', 1)
                .attr('rx', 3)
                .on('mouseover', function(event, d) {{
                    d3.select(this).attr('stroke', '#000').attr('stroke-width', 2);
                    const tooltip = document.getElementById('sankeyTooltip');
                    tooltip.style.display = 'block';
                    tooltip.innerHTML = `<b>${{d.data.name}}</b><br>Протокол: ${{d.data.protocol}}<br>Использований: ${{d.data.count}}<br>Доля: ${{d.data.percentage}}%`;
                }})
                .on('mousemove', function(event) {{
                    const tooltip = document.getElementById('sankeyTooltip');
                    tooltip.style.left = (event.pageX + 12) + 'px';
                    tooltip.style.top = (event.pageY - 10) + 'px';
                }})
                .on('mouseout', function() {{
                    d3.select(this).attr('stroke', '#fff').attr('stroke-width', 1);
                    document.getElementById('sankeyTooltip').style.display = 'none';
                }});

            // Text labels (only if cell is big enough)
            cells.append('text')
                .attr('x', 6)
                .attr('y', 16)
                .attr('fill', textColor)
                .attr('font-size', '11px')
                .attr('font-family', 'Segoe UI, sans-serif')
                .text(d => {{
                    const w = d.x1 - d.x0;
                    const h = d.y1 - d.y0;
                    if (w < 40 || h < 20) return '';
                    const maxChars = Math.floor(w / 7);
                    return d.data.name.length > maxChars ? d.data.name.substring(0, maxChars - 2) + '..' : d.data.name;
                }});

            cells.append('text')
                .attr('x', 6)
                .attr('y', 32)
                .attr('fill', textColor)
                .attr('font-size', '10px')
                .attr('font-family', 'Segoe UI, sans-serif')
                .attr('opacity', 0.8)
                .text(d => {{
                    const w = d.x1 - d.x0;
                    const h = d.y1 - d.y0;
                    if (w < 50 || h < 40) return '';
                    return `${{d.data.count}} (${{d.data.percentage}}%)`;
                }});

            // Legend
            const legendG = svg.append('g').attr('transform', `translate(${{width - 130}}, 10)`);
            const legendItems = [
                {{label: 'TCP', color: protoColors['tcp']}},
                {{label: 'UDP', color: protoColors['udp']}},
                {{label: 'ICMP', color: protoColors['icmp']}},
                {{label: 'IP/Other', color: protoColors['ip']}}
            ];
            legendItems.forEach((item, i) => {{
                const g = legendG.append('g').attr('transform', `translate(0, ${{i * 22}})`);
                g.append('rect').attr('width', 14).attr('height', 14).attr('fill', item.color).attr('rx', 2);
                g.append('text').attr('x', 20).attr('y', 12).attr('fill', textColor).attr('font-size', '11px').text(item.label);
            }});

            // Handle resize
            window.addEventListener('resize', () => {{
                if (currentView === 'services' && servicesRendered) {{
                    servicesRendered = false;
                    renderServiceTreemap();
                    servicesRendered = true;
                }}
            }});
        }}

        // ===== Risk Severity Donut Chart (vanilla SVG) =====
        function renderRiskDonut() {{
            const container = document.getElementById('risksDonut');
            if (!riskSeverityData || riskSeverityData.length === 0 || riskSeverityData.every(d => d.count === 0)) {{
                container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#999;font-size:16px;">Нет данных о рисках</div>';
                return;
            }}

            container.innerHTML = '';
            const width = container.clientWidth || 800;
            const height = container.clientHeight || 500;
            const size = Math.min(width, height) * 0.7;
            const radius = size / 2;
            const innerRadius = radius * 0.55;
            const cx = width / 2 - 80;
            const cy = height / 2;

            const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            svg.setAttribute('width', width);
            svg.setAttribute('height', height);
            container.appendChild(svg);

            const isDark = document.body.classList.contains('dark-theme');
            const textColor = isDark ? '#ddd' : '#333';

            // Calculate arc paths
            const total = riskSeverityData.reduce((s, d) => s + d.count, 0);
            let startAngle = -Math.PI / 2;

            const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            g.setAttribute('transform', `translate(${{cx}},${{cy}})`);
            svg.appendChild(g);

            riskSeverityData.forEach(d => {{
                if (d.count === 0) return;
                const sliceAngle = (d.count / total) * 2 * Math.PI;
                const endAngle = startAngle + sliceAngle;

                const x1 = radius * Math.cos(startAngle);
                const y1 = radius * Math.sin(startAngle);
                const x2 = radius * Math.cos(endAngle);
                const y2 = radius * Math.sin(endAngle);
                const x3 = innerRadius * Math.cos(endAngle);
                const y3 = innerRadius * Math.sin(endAngle);
                const x4 = innerRadius * Math.cos(startAngle);
                const y4 = innerRadius * Math.sin(startAngle);

                const largeArc = sliceAngle > Math.PI ? 1 : 0;

                const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                const d_attr = `M ${{x1}} ${{y1}} ` +
                    `A ${{radius}} ${{radius}} 0 ${{largeArc}} 1 ${{x2}} ${{y2}} ` +
                    `L ${{x3}} ${{y3}} ` +
                    `A ${{innerRadius}} ${{innerRadius}} 0 ${{largeArc}} 0 ${{x4}} ${{y4}} Z`;
                path.setAttribute('d', d_attr);
                path.setAttribute('fill', d.color);
                path.setAttribute('stroke', isDark ? '#1a1a2e' : '#fff');
                path.setAttribute('stroke-width', '2');
                path.style.cursor = 'pointer';
                path.style.transition = 'transform 0.15s';

                path.addEventListener('mouseover', function(event) {{
                    this.style.transform = 'scale(1.05)';
                    this.setAttribute('stroke', '#000');
                    this.setAttribute('stroke-width', '3');
                    const tooltip = document.getElementById('sankeyTooltip');
                    tooltip.style.display = 'block';
                    tooltip.innerHTML = `<b>${{d.severity}}</b><br>Рёбер: ${{d.count}}<br>Доля: ${{d.percentage}}%`;
                }});
                path.addEventListener('mousemove', function(event) {{
                    const tooltip = document.getElementById('sankeyTooltip');
                    tooltip.style.left = (event.pageX + 12) + 'px';
                    tooltip.style.top = (event.pageY - 10) + 'px';
                }});
                path.addEventListener('mouseout', function() {{
                    this.style.transform = 'scale(1)';
                    this.setAttribute('stroke', isDark ? '#1a1a2e' : '#fff');
                    this.setAttribute('stroke-width', '2');
                    document.getElementById('sankeyTooltip').style.display = 'none';
                }});

                g.appendChild(path);
                startAngle = endAngle;
            }});

            // Center text — total issues
            const centerText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            centerText.setAttribute('x', cx);
            centerText.setAttribute('y', cy - 8);
            centerText.setAttribute('text-anchor', 'middle');
            centerText.setAttribute('font-size', '28');
            centerText.setAttribute('font-weight', 'bold');
            centerText.setAttribute('fill', textColor);
            centerText.setAttribute('font-family', 'Segoe UI, sans-serif');
            centerText.textContent = total;
            svg.appendChild(centerText);

            const centerLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            centerLabel.setAttribute('x', cx);
            centerLabel.setAttribute('y', cy + 16);
            centerLabel.setAttribute('text-anchor', 'middle');
            centerLabel.setAttribute('font-size', '13');
            centerLabel.setAttribute('fill', textColor);
            centerLabel.setAttribute('opacity', '0.7');
            centerLabel.setAttribute('font-family', 'Segoe UI, sans-serif');
            centerLabel.textContent = 'issues';
            svg.appendChild(centerLabel);

            // Legend (right side)
            const lgG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            lgG.setAttribute('transform', `translate(${{cx + radius + 40}},${{cy - 70}})`);
            svg.appendChild(lgG);

            riskSeverityData.forEach((d, i) => {{
                const y = i * 26;
                const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
                rect.setAttribute('x', 0);
                rect.setAttribute('y', y);
                rect.setAttribute('width', 16);
                rect.setAttribute('height', 16);
                rect.setAttribute('fill', d.color);
                rect.setAttribute('rx', 3);
                lgG.appendChild(rect);

                const txt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                txt.setAttribute('x', 24);
                txt.setAttribute('y', y + 13);
                txt.setAttribute('fill', textColor);
                txt.setAttribute('font-size', '12');
                txt.setAttribute('font-family', 'Segoe UI, sans-serif');
                txt.textContent = `${{d.severity}}: ${{d.count}} (${{d.percentage}}%)`;
                lgG.appendChild(txt);
            }});

            // Handle resize
            window.addEventListener('resize', () => {{
                if (currentView === 'risks' && risksRendered) {{
                    risksRendered = false;
                    renderRiskDonut();
                    risksRendered = true;
                }}
            }});
        }}
        
        // Переключение темы
        function toggleTheme() {{
            document.body.classList.toggle('dark-theme');
        }}
    </script>
</body>
</html>"""
    
    def _generate_zone_options(self, nodes_data: List[Dict]) -> str:
        """Генерирует HTML опции для фильтра зон."""
        zones = sorted(set((n.get('group') or 'Unknown') for n in nodes_data))
        return ''.join(f'<option value="{z}">{z}</option>' for z in zones)
    
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
