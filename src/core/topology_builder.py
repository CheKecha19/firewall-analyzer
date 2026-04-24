"""
Построитель топологии сети.
"""
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
import networkx as nx
from ..models.interface import Interface
from ..models.route import StaticRoute
from ..models.device import NetworkDevice


@dataclass
class NetworkLink:
    """Представление связи между устройствами через сеть."""
    network: str  # CIDR сети
    devices: List[Tuple[str, Interface]] = field(default_factory=list)  # (device_id, interface)
    
    def add_device(self, device_id: str, interface: Interface):
        """Добавляет устройство к сети."""
        self.devices.append((device_id, interface))
    
    @property
    def device_count(self) -> int:
        return len(self.devices)
    
    def __hash__(self):
        return hash(self.network)
    
    def __eq__(self, other):
        if not isinstance(other, NetworkLink):
            return False
        return self.network == other.network


class TopologyBuilder:
    """Строитель топологической карты сети."""
    
    def __init__(self):
        self.devices: Dict[str, NetworkDevice] = {}
        self.networks: Dict[str, NetworkLink] = {}
        self.topology_graph: Optional[nx.Graph] = None
    
    def add_device(self, device: NetworkDevice):
        """Добавляет устройство в топологию."""
        self.devices[device.id] = device
        self._process_device_networks(device)
    
    def add_device_from_parsed(
        self,
        device_id: str,
        vendor: str,
        hostname: Optional[str],
        interfaces: List[Interface],
        routes: List[StaticRoute],
        mgmt_ip: Optional[str] = None
    ):
        """Создаёт и добавляет устройство из распарсенных данных."""
        device = NetworkDevice(
            id=device_id,
            vendor=vendor,
            hostname=hostname,
            interfaces=interfaces,
            static_routes=routes,
            mgmt_ip=mgmt_ip
        )
        self.add_device(device)
    
    def _process_device_networks(self, device: NetworkDevice):
        """Обрабатывает сети устройства."""
        for interface in device.interfaces:
            if interface.ip_address:
                # Добавляем в сеть
                if interface.ip_address not in self.networks:
                    self.networks[interface.ip_address] = NetworkLink(
                        network=interface.ip_address
                    )
                self.networks[interface.ip_address].add_device(device.id, interface)
    
    def build_topology_graph(self) -> nx.Graph:
        """Строит граф топологии сети."""
        G = nx.Graph()
        
        # Добавляем узлы устройств
        for device_id, device in self.devices.items():
            label = device.hostname or device_id
            G.add_node(
                device_id,
                type='device',
                label=label,
                vendor=device.vendor,
                mgmt_ip=device.mgmt_ip,
                title=self._build_device_tooltip(device)
            )
        
        # Добавляем узлы сетей и связи
        for network_cidr, link in self.networks.items():
            if link.device_count >= 2:
                # Сеть соединяет несколько устройств
                network_node_id = f"net:{network_cidr}"
                G.add_node(
                    network_node_id,
                    type='network',
                    label=network_cidr,
                    title=f"Network: {network_cidr}\nDevices: {link.device_count}"
                )
                
                # Соединяем устройства с сетью
                for device_id, interface in link.devices:
                    G.add_edge(
                        device_id,
                        network_node_id,
                        interface=interface.name,
                        ip=interface.ip_only or 'N/A',
                        title=f"{interface.name}: {interface.ip_address}"
                    )
        
        # Добавляем связи через маршруты
        self._add_route_links(G)
        
        self.topology_graph = G
        return G
    
    def _add_route_links(self, G: nx.Graph):
        """Добавляет связи на основе статических маршрутов."""
        for device_id, device in self.devices.items():
            for route in device.static_routes:
                next_hop_ip = route.next_hop_ip
                if next_hop_ip:
                    # Ищем устройство с этим IP
                    for other_id, other_device in self.devices.items():
                        if other_id == device_id:
                            continue
                        
                        # Проверяем, есть ли интерфейс с этим IP
                        for iface in other_device.interfaces:
                            if iface.ip_only == next_hop_ip:
                                # Добавляем связь через маршрут
                                if not G.has_edge(device_id, other_id):
                                    G.add_edge(
                                        device_id,
                                        other_id,
                                        type='route',
                                        destination=route.destination,
                                        next_hop=next_hop_ip,
                                        title=f"Route to {route.destination} via {next_hop_ip}"
                                    )
                                break
    
    def _build_device_tooltip(self, device: NetworkDevice) -> str:
        """Строит tooltip для устройства."""
        lines = [
            f"Device: {device.hostname or device.id}",
            f"Vendor: {device.vendor}",
            f"Management IP: {device.mgmt_ip or 'N/A'}",
            "",
            "Interfaces:"
        ]
        
        for iface in device.interfaces:
            ip_str = iface.ip_address or 'no IP'
            zone_str = f" [{iface.zone}]" if iface.zone else ""
            lines.append(f"  {iface.name}: {ip_str}{zone_str}")
        
        if device.static_routes:
            lines.append("")
            lines.append("Static Routes:")
            for route in device.static_routes:
                lines.append(f"  {route.destination} -> {route.next_hop}")
        
        return "\n".join(lines)
    
    def find_path_between_devices(
        self,
        source_id: str,
        target_id: str
    ) -> Optional[List[str]]:
        """Находит путь между устройствами в топологии."""
        if self.topology_graph is None:
            self.build_topology_graph()
        
        try:
            path = nx.shortest_path(self.topology_graph, source_id, target_id)
            return path
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None
    
    def get_device_neighbors(self, device_id: str) -> List[str]:
        """Возвращает список соседей устройства."""
        if self.topology_graph is None:
            self.build_topology_graph()
        
        if device_id not in self.topology_graph:
            return []
        
        return list(self.topology_graph.neighbors(device_id))
    
    def get_networks_for_device(self, device_id: str) -> List[str]:
        """Возвращает список сетей, к которым подключено устройство."""
        if device_id not in self.devices:
            return []
        
        networks = []
        device = self.devices[device_id]
        for iface in device.interfaces:
            if iface.ip_address:
                networks.append(iface.ip_address)
        
        return networks
    
    def export_to_visjs_data(self) -> Tuple[List[Dict], List[Dict]]:
        """Экспортирует топологию в формат Vis.js."""
        if self.topology_graph is None:
            self.build_topology_graph()
        
        nodes = []
        edges = []
        
        # Цвета для типов узлов
        colors = {
            'device': '#90EE90',      # Светло-зелёный
            'network': '#87CEEB',     # Голубой
        }
        
        # Формы для типов узлов
        shapes = {
            'device': 'box',
            'network': 'dot',
        }
        
        for node_id, data in self.topology_graph.nodes(data=True):
            node_type = data.get('type', 'unknown')
            
            node = {
                'id': node_id,
                'label': data.get('label', str(node_id)),
                'title': data.get('title', ''),
                'color': colors.get(node_type, '#D3D3D3'),
                'shape': shapes.get(node_type, 'dot'),
            }
            
            # Для сетей делаем меньше
            if node_type == 'network':
                node['size'] = 15
            
            nodes.append(node)
        
        for src, dst, data in self.topology_graph.edges(data=True):
            edge = {
                'from': src,
                'to': dst,
                'title': data.get('title', ''),
            }
            
            # Если есть интерфейс - это подключение к сети
            if 'interface' in data:
                edge['label'] = data['interface']
                edge['color'] = '#666'
            elif data.get('type') == 'route':
                edge['color'] = '#FF8C00'  # Оранжевый для маршрутов
                edge['dashes'] = True
            
            edges.append(edge)
        
        return nodes, edges
    
    def to_dict(self) -> Dict:
        """Сериализует топологию в словарь."""
        return {
            'devices': {
                device_id: {
                    'id': device.id,
                    'vendor': device.vendor,
                    'hostname': device.hostname,
                    'mgmt_ip': device.mgmt_ip,
                    'interfaces': [
                        {
                            'name': iface.name,
                            'ip_address': iface.ip_address,
                            'zone': iface.zone,
                            'description': iface.description,
                        }
                        for iface in device.interfaces
                    ],
                    'static_routes': [
                        {
                            'destination': route.destination,
                            'next_hop': route.next_hop,
                            'admin_distance': route.admin_distance,
                        }
                        for route in device.static_routes
                    ]
                }
                for device_id, device in self.devices.items()
            },
            'networks': {
                cidr: {
                    'network': link.network,
                    'devices': [
                        {'device_id': did, 'interface': iface.name}
                        for did, iface in link.devices
                    ]
                }
                for cidr, link in self.networks.items()
            }
        }
