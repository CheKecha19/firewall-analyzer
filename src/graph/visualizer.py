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
                       topology_data=None) -> Optional[Path]:
        """Генерирует полноценный HTML-отчёт используя ui_template.html (как веб-режим)."""
        import json

        # ── Prepare nodes JSON ──
        nodes_data = []
        for node, data in self.graph.nodes(data=True):
            node_type = data.get('type', data.get('endpoint_type', 'unknown'))
            zone = data.get('zone', 'Unknown')
            risk_score = data.get('risk_score', 0)

            label = str(node)
            if node_type in ('host', 'workstation'):
                label = data.get('hostname', str(node))

            nodes_data.append({
                'id': str(node),
                'label': label,
                'group': zone,
                'type': node_type,
                'risk_score': risk_score,
                'zone': zone,
                'title': f"{label}<br>Zone: {zone}<br>Type: {node_type}<br>Risk: {risk_score}"
            })

        # ── Prepare edges JSON ──
        edges_data = []
        for src, dst, data in self.graph.edges(data=True):
            risk = data.get('risk_score', 0)
            services = data.get('services', [])
            rules = data.get('rules', [])

            edge_title = f"Risk: {risk}/10"
            if services:
                edge_title += f"\nServices: {', '.join(str(s) for s in services[:5])}"
            if rules:
                edge_title += f"\nRules: {', '.join(str(r) for r in rules[:5])}"

            edges_data.append({
                'from': str(src),
                'to': str(dst),
                'color': '#666666',
                'width': 1 + risk * 0.3,
                'title': edge_title,
                'riskScore': risk
            })

        # ── Prepare rules JSON ──
        rules_table = []
        if self.rules:
            for rule in self.rules:
                rules_table.append({
                    'name': rule.name,
                    'source': ', '.join(str(s) for s in rule.sources[:3]),
                    'destination': ', '.join(str(d) for d in rule.destinations[:3]),
                    'service': ', '.join(str(s) for s in rule.services[:3]),
                    'action': rule.action
                })

        # ── Prepare audit JSON (from SecurityAuditor if available) ──
        audit_data = []
        try:
            from src.core.security_auditor import SecurityAuditor
            auditor = SecurityAuditor(self.rules, self.graph)
            report = auditor.run_full_audit()
            # run_full_audit returns dict: {'summary': ..., 'issues': [dict, ...]}
            for f in report.get('issues', []):
                audit_data.append({
                    'type': f.get('type', ''),
                    'severity': f.get('severity', 'info'),
                    'description': f.get('description', ''),
                    'rule_name': f.get('rule', ''),
                    'recommendation': f.get('recommendation', '')
                })
        except Exception as e:
            print(f"[AUDIT] Skipped in generate_html: {e}")
        except Exception as e:
            print(f"[AUDIT] Skipped in generate_html: {e}")

        # ── Stats ──
        all_zones = sorted(set(data.get('zone') or 'Unknown' for _, data in self.graph.nodes(data=True)))
        stats = {
            'total_rules': len(self.rules),
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'zones': all_zones
        }

        # ── Static mode: pre-load all API data for offline HTML ──
        # Dashboard data
        try:
            from src.core.dashboard import get_dashboard_json
            dashboard_data = get_dashboard_json(
                issues=audit_data,
                rules=rules_table,
                graph_stats=stats,
                zones=all_zones
            )
            dashboard_json = json.dumps(dashboard_data, ensure_ascii=False)
        except Exception as e:
            print(f"[WARN] Dashboard generation failed: {e}")
            dashboard_json = '{}'

        # Risk severity data
        risk_severity_data = self._generate_risk_severity_data()
        risk_severity_json = json.dumps(risk_severity_data, ensure_ascii=False)

        # Services data
        service_data = self._generate_service_data()
        service_json = json.dumps(service_data, ensure_ascii=False)

        # MITRE data
        try:
            from src.core.mitre_mapper import MitreMapper
            from dataclasses import asdict
            mapper = MitreMapper()
            mitre_report = mapper.map_all(audit_data)
            mitre_data = [asdict(m) for m in (mitre_report.matches if mitre_report else [])]
            mitre_json = json.dumps(mitre_data, ensure_ascii=False)
        except Exception as e:
            print(f"[WARN] MITRE mapping failed: {e}")
            mitre_json = '[]'

        # STATIC_MODE flag
        static_mode = 'true'

        # ── Zones options ──
        zones = all_zones
        zones_options = ''.join(f'<option value="{z}">{z}</option>\n' for z in zones)

        # ── Load template and inject data ──
        template_path = Path(__file__).parent.parent / 'api' / 'ui_template.html'
        if not template_path.exists():
            print("[ERROR] UI template not found:", template_path)
            return None

        template = template_path.read_text(encoding='utf-8')

        html = template.replace('__NODES_JSON__', json.dumps(nodes_data, ensure_ascii=False))
        html = html.replace('__EDGES_JSON__', json.dumps(edges_data, ensure_ascii=False))
        html = html.replace('__RULES_JSON__', json.dumps(rules_table, ensure_ascii=False))
        html = html.replace('__AUDIT_JSON__', json.dumps(audit_data, ensure_ascii=False))
        html = html.replace('__STATS_JSON__', json.dumps(stats, ensure_ascii=False))
        html = html.replace('__ZONES_OPTIONS__', zones_options)
        html = html.replace('__DASHBOARD_JSON__', dashboard_json)
        html = html.replace('__RISK_SEVERITY_JSON__', risk_severity_json)
        html = html.replace('__SERVICES_JSON__', service_json)
        html = html.replace('__MITRE_JSON__', mitre_json)
        html = html.replace('__STATIC_MODE__', static_mode)

        # ── Write output ──
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding='utf-8')
        print(f"[OK] HTML report: {output_path}")
        return output_path

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
