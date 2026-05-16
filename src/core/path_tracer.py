"""
Path Tracer with ACL Evaluation
Трассирует путь пакета через сеть с учётом ACL/Firewall правил.
"""

import ipaddress
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum


class PathResult(Enum):
    ALLOW = "allow"
    DENY = "deny"
    NO_ROUTE = "no_route"
    ACL_DENY = "acl_deny"
    NAT_REQUIRED = "nat_required"


@dataclass
class Hop:
    """Шаг трассировки."""
    device: str
    interface_in: str
    interface_out: Optional[str]
    action: str  # permit/deny/route/nat
    rule_id: Optional[str]
    rule_name: Optional[str]
    details: str
    risk: float = 0.0


@dataclass
class PathTrace:
    """Результат трассировки пути."""
    source: str
    destination: str
    port: int
    protocol: str
    result: PathResult
    hops: List[Hop] = field(default_factory=list)
    total_risk: float = 0.0
    duration_ms: int = 0
    recommendation: str = ""


class PathTracer:
    """Трассировщик пути с ACL evaluation."""
    
    def __init__(self, rules: List, topology=None, topology_builder=None):
        self.rules = rules
        self.topology = topology
        self.topology_builder = topology_builder  # TopologyBuilder instance
        self.nat_table: Dict[str, str] = {}  # original -> translated
    
    def trace(self, source: str, destination: str, 
              port: int = 80, protocol: str = "tcp") -> PathTrace:
        """Трассирует путь от source к destination."""
        
        trace = PathTrace(
            source=source,
            destination=destination,
            port=port,
            protocol=protocol,
            result=PathResult.NO_ROUTE,
            hops=[]
        )
        
        # Определяем начальное устройство
        src_device = self._find_device_for_ip(source)
        dst_device = self._find_device_for_ip(destination)
        
        if not src_device:
            trace.result = PathResult.NO_ROUTE
            trace.recommendation = f"Source {source} not in network"
            return trace
        
        # Трассировка
        current_ip = source
        current_device = src_device
        visited = set()
        
        while current_device and current_device not in visited:
            visited.add(current_device)
            
            # 1. Проверяем ACL на входе
            acl_result = self._check_acl(current_device, current_ip, destination, 
                                         port, protocol, "in")
            
            if acl_result.action == "deny":
                trace.hops.append(Hop(
                    device=current_device,
                    interface_in=acl_result.interface,
                    interface_out=None,
                    action="deny",
                    rule_id=acl_result.rule_id,
                    rule_name=acl_result.rule_name,
                    details=f"ACL denied: {acl_result.details}",
                    risk=10.0
                ))
                trace.result = PathResult.ACL_DENY
                trace.recommendation = f"Check ACL on {current_device}"
                return trace
            
            # 2. Проверяем маршрутизацию
            route = self._find_route(current_device, destination)
            
            if not route:
                trace.hops.append(Hop(
                    device=current_device,
                    interface_in=acl_result.interface,
                    interface_out=None,
                    action="no_route",
                    rule_id=None,
                    rule_name=None,
                    details=f"No route to {destination}",
                    risk=0.0
                ))
                trace.result = PathResult.NO_ROUTE
                trace.recommendation = f"Add route on {current_device}"
                return trace
            
            # 3. Проверяем ACL на выходе
            out_acl = self._check_acl(current_device, current_ip, destination,
                                      port, protocol, "out")
            
            if out_acl.action == "deny":
                trace.hops.append(Hop(
                    device=current_device,
                    interface_in=acl_result.interface,
                    interface_out=route.interface,
                    action="deny",
                    rule_id=out_acl.rule_id,
                    rule_name=out_acl.rule_name,
                    details=f"Outbound ACL denied: {out_acl.details}",
                    risk=10.0
                ))
                trace.result = PathResult.ACL_DENY
                trace.recommendation = f"Check outbound ACL on {current_device}"
                return trace
            
            # 4. Проверяем NAT
            nat = self._check_nat(current_device, current_ip, destination)
            
            # Добавляем hop
            trace.hops.append(Hop(
                device=current_device,
                interface_in=acl_result.interface,
                interface_out=route.interface,
                action="permit" if not nat else "nat",
                rule_id=acl_result.rule_id,
                rule_name=acl_result.rule_name,
                details=f"Route via {route.next_hop}" + (f", NAT to {nat}" if nat else ""),
                risk=acl_result.risk
            ))
            
            # Переходим к следующему hop
            if nat:
                current_ip = nat
            
            if route.next_hop == destination or route.next_hop == "0.0.0.0":
                # Достигли назначения
                trace.result = PathResult.ALLOW
                trace.recommendation = "Path is clear"
                break
            
            # Находим следующее устройство
            next_device = self._find_device_for_ip(route.next_hop)
            if not next_device:
                # Проверяем, не является ли next_hop destination
                if self._ip_in_network(destination, route.next_hop, route.mask):
                    trace.result = PathResult.ALLOW
                    trace.recommendation = "Path is clear"
                    break
                trace.result = PathResult.NO_ROUTE
                trace.recommendation = f"No device for next-hop {route.next_hop}"
                return trace
            
            current_device = next_device
        
        # Рассчитываем общий риск
        trace.total_risk = sum(h.risk for h in trace.hops) / max(len(trace.hops), 1)
        
        return trace
    
    def _find_device_for_ip(self, ip: str) -> Optional[str]:
        """Находит устройство по IP."""
        if not self.topology:
            return None
        
        for hostname, device in self.topology.items():
            for iface_name, iface in device.get('interfaces', {}).items():
                if iface.get('ip_address') == ip:
                    return hostname
                # Проверяем сеть
                if iface.get('ip_address') and iface.get('subnet'):
                    if self._ip_in_network(ip, iface['ip_address'], iface['subnet']):
                        return hostname
        return None
    
    def _ip_in_network(self, ip: str, network_ip: str, mask: str) -> bool:
        """Проверяет, находится ли IP в сети."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(f"{network_ip}/{mask}", strict=False)
            return ip_obj in network
        except:
            return False
    
    def _check_acl(self, device: str, src: str, dst: str, 
                   port: int, protocol: str, direction: str):
        """Проверяет ACL."""
        # Ищем правила для устройства
        device_rules = [r for r in self.rules if hasattr(r, 'device') and r.device == device]
        
        if not device_rules:
            # No ACL = permit
            return type('ACLResult', (), {
                'action': 'permit',
                'interface': 'any',
                'rule_id': None,
                'rule_name': 'default',
                'details': 'No ACL configured',
                'risk': 0.0
            })()
        
        for rule in device_rules:
            if self._rule_matches(rule, src, dst, port, protocol):
                action = getattr(rule, 'action', 'deny')
                return type('ACLResult', (), {
                    'action': action,
                    'interface': getattr(rule, 'interface', 'any'),
                    'rule_id': getattr(rule, 'id', None),
                    'rule_name': getattr(rule, 'name', 'unknown'),
                    'details': f"Rule {getattr(rule, 'name', 'unknown')}",
                    'risk': getattr(rule, 'risk_score', 5.0)
                })()
        
        # Default deny
        return type('ACLResult', (), {
            'action': 'deny',
            'interface': 'any',
            'rule_id': None,
            'rule_name': 'default',
            'details': 'No matching rule (implicit deny)',
            'risk': 0.0
        })()
    
    def _rule_matches(self, rule, src: str, dst: str, port: int, protocol: str) -> bool:
        """Проверяет, соответствует ли пакет правилу."""
        # Проверяем source
        rule_src = getattr(rule, 'source', 'any')
        if rule_src != 'any' and rule_src != src:
            if not self._ip_in_network(src, rule_src, getattr(rule, 'src_mask', '255.255.255.255')):
                return False
        
        # Проверяем destination
        rule_dst = getattr(rule, 'destination', 'any')
        if rule_dst != 'any' and rule_dst != dst:
            if not self._ip_in_network(dst, rule_dst, getattr(rule, 'dst_mask', '255.255.255.255')):
                return False
        
        # Проверяем port
        rule_port = getattr(rule, 'service', getattr(rule, 'port', 'any'))
        if str(rule_port) != 'any' and str(rule_port) != str(port):
            return False
        
        # Проверяем protocol
        rule_proto = getattr(rule, 'protocol', 'any')
        if rule_proto != 'any' and rule_proto != protocol:
            return False
        
        return True
    
    def _find_route(self, device: str, destination: str):
        """Находит маршрут для destination."""
        if not self.topology or device not in self.topology:
            return None
        
        routes = self.topology[device].get('routes', [])
        
        # Сначала ищем точное совпадение
        for route in routes:
            if route.get('destination') == destination:
                return type('Route', (), {
                    'next_hop': route.get('next_hop', destination),
                    'interface': route.get('interface', 'unknown'),
                    'mask': route.get('mask', '255.255.255.255')
                })()
        
        # Затем ищем по сети
        for route in routes:
            if route.get('destination') == '0.0.0.0':
                return type('Route', (), {
                    'next_hop': route.get('next_hop'),
                    'interface': route.get('interface', 'unknown'),
                    'mask': '0.0.0.0'
                })()
        
        return None
    
    def _check_nat(self, device: str, src: str, dst: str) -> Optional[str]:
        """Проверяет NAT."""
        # Заглушка — реальная реализация требует парсинга NAT rules
        return self.nat_table.get(src)

    def find_all_paths(self, source: str, destination: str,
                       port: int = 80, protocol: str = "tcp",
                       max_paths: int = 5) -> List[PathTrace]:
        """
        Находит все возможные пути между source и destination (BFS).
        Использует топологию для построения графа и поиска альтернативных маршрутов.
        """
        paths = []

        if not self.topology_builder:
            # Fallback: single-trace mode
            trace = self.trace(source, destination, port, protocol)
            return [trace]

        try:
            import networkx as nx

            # Получаем граф топологии
            if self.topology_builder.topology_graph is None:
                self.topology_builder.build_topology_graph()

            G = self.topology_builder.topology_graph
            if G is None:
                trace = self.trace(source, destination, port, protocol)
                return [trace]

            # Находим source/dest устройства
            src_device = self._find_device_for_ip(source)
            dst_device = self._find_device_for_ip(destination)

            if not src_device or not dst_device:
                trace = self.trace(source, destination, port, protocol)
                return [trace]

            if src_device not in G or dst_device not in G:
                trace = self.trace(source, destination, port, protocol)
                return [trace]

            # BFS: находим все простые пути
            all_simple = list(nx.all_simple_paths(G, src_device, dst_device, cutoff=8))[:max_paths]

            for path_devices in all_simple:
                trace = PathTrace(
                    source=source,
                    destination=destination,
                    port=port,
                    protocol=protocol,
                    result=PathResult.ALLOW,
                    hops=[]
                )

                blocked = False
                for i, device in enumerate(path_devices):
                    topo_dev = self.topology[device] if self.topology and device in self.topology else {}
                    next_hop = path_devices[i + 1] if i + 1 < len(path_devices) else None

                    # Check ACL on this device
                    acl_result = self._check_acl(device, source, destination, port, protocol, "in")

                    if acl_result.action == "deny":
                        trace.hops.append(Hop(
                            device=device,
                            interface_in=acl_result.interface,
                            interface_out=None,
                            action="deny",
                            rule_id=acl_result.rule_id,
                            rule_name=acl_result.rule_name,
                            details=f"ACL denied: {acl_result.details}",
                            risk=10.0
                        ))
                        trace.result = PathResult.ACL_DENY
                        trace.recommendation = f"Check ACL on {device}"
                        blocked = True
                        break

                    # Determine out interface
                    out_iface = None
                    route_details = "direct"
                    if next_hop:
                        next_topo = self.topology.get(next_hop, {}) if self.topology else {}
                        # Try to find connecting interface
                        for iface_name, iface in topo_dev.get('interfaces', {}).items():
                            iface_ip = iface.get('ip_address', '')
                            for nif_name, nif in next_topo.get('interfaces', {}).items():
                                nif_ip = nif.get('ip_address', '')
                                if iface_ip and nif_ip:
                                    try:
                                        net1 = ipaddress.ip_network(f"{iface_ip}/{iface.get('subnet', '24')}", strict=False)
                                        if ipaddress.ip_address(nif_ip.split('/')[0]) in net1:
                                            out_iface = iface_name
                                            route_details = f"to {next_hop} via {iface_name}"
                                            break
                                    except:
                                        pass

                    trace.hops.append(Hop(
                        device=device,
                        interface_in=acl_result.interface,
                        interface_out=out_iface,
                        action="forward",
                        rule_id=acl_result.rule_id,
                        rule_name=acl_result.rule_name,
                        details=route_details,
                        risk=0.5
                    ))

                if not blocked:
                    trace.result = PathResult.ALLOW
                    trace.recommendation = f"Path via {' → '.join(path_devices)}"

                trace.total_risk = sum(h.risk for h in trace.hops) / max(len(trace.hops), 1)
                paths.append(trace)

            return paths if paths else [self.trace(source, destination, port, protocol)]

        except ImportError:
            trace = self.trace(source, destination, port, protocol)
            return [trace]

    def to_visjs(self, trace: PathTrace, output_path: str = None) -> Dict:
        """
        Конвертирует результат трассировки в Vis.js формат для визуализации.

        Returns:
            Dict с 'nodes' и 'edges' для Vis.js
        """
        nodes = []
        edges = []
        node_ids = set()

        colors = {
            PathResult.ALLOW: '#2ecc71',
            PathResult.DENY: '#e74c3c',
            PathResult.NO_ROUTE: '#f39c12',
            PathResult.ACL_DENY: '#e74c3c',
            PathResult.NAT_REQUIRED: '#9b59b6',
        }

        # Добавляем source и destination как start/end ноды
        src_id = f"src_{trace.source}"
        dst_id = f"dst_{trace.destination}"

        nodes.append({
            'id': src_id,
            'label': f"SOURCE\n{trace.source}",
            'group': 'source',
            'color': '#3498db',
            'shape': 'star',
            'size': 30,
            'title': f"Source: {trace.source}<br>Port: {trace.port}<br>Protocol: {trace.protocol}"
        })
        nodes.append({
            'id': dst_id,
            'label': f"DEST\n{trace.destination}",
            'group': 'destination',
            'color': '#e67e22',
            'shape': 'star',
            'size': 30,
            'title': f"Destination: {trace.destination}<br>Port: {trace.port}"
        })

        prev_id = src_id

        for i, hop in enumerate(trace.hops):
            hop_id = f"hop_{i}_{hop.device}"
            color = '#2ecc71' if hop.action in ('permit', 'forward') else '#e74c3c'

            nodes.append({
                'id': hop_id,
                'label': f"{hop.device}\n{hop.action}",
                'group': 'device',
                'color': color,
                'shape': 'box',
                'size': 25,
                'title': f"<b>{hop.device}</b><br>"
                         f"Action: {hop.action}<br>"
                         f"In: {hop.interface_in}<br>"
                         f"Out: {hop.interface_out}<br>"
                         f"Rule: {hop.rule_name or 'N/A'}<br>"
                         f"Details: {hop.details}<br>"
                         f"Risk: {hop.risk}"
            })

            # Edge from previous to this hop
            edge_color = '#2ecc71' if hop.action in ('permit', 'forward') else '#e74c3c'
            edges.append({
                'from': prev_id,
                'to': hop_id,
                'color': edge_color,
                'arrows': 'to',
                'width': 3,
                'label': f"Hop {i + 1}"
            })

            prev_id = hop_id

        # Final edge to destination
        result_color = colors.get(trace.result, '#95a5a6')
        edges.append({
            'from': prev_id,
            'to': dst_id,
            'color': result_color,
            'arrows': 'to',
            'width': 3,
            'dashes': trace.result != PathResult.ALLOW,
            'label': trace.result.value.upper()
        })

        result = {'nodes': nodes, 'edges': edges}

        if output_path:
            import json
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)

        return result


# Экспорт
__all__ = ['PathTracer', 'PathTrace', 'Hop', 'PathResult']
