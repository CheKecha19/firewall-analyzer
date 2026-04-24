"""
Парсер физической топологии и L3 маршрутов.
Извлекает интерфейсы, VLAN, статические маршруты, соседей LLDP/CDP.
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from ipaddress import ip_interface, ip_network


@dataclass
class Interface:
    """Сетевой интерфейс."""
    name: str
    ip_address: Optional[str] = None
    subnet: Optional[str] = None
    vlan: Optional[int] = None
    status: str = 'unknown'  # up/down/admin-down
    speed: str = 'unknown'  # 1G/10G/100G
    duplex: str = 'unknown'  # full/half
    description: str = ''
    is_trunk: bool = False
    trunk_vlans: List[int] = None
    native_vlan: Optional[int] = None
    is_lag: bool = False
    lag_members: List[str] = None
    
    def __post_init__(self):
        if self.trunk_vlans is None:
            self.trunk_vlans = []
        if self.lag_members is None:
            self.lag_members = []


@dataclass
class StaticRoute:
    """Статический маршрут."""
    destination: str
    next_hop: str
    mask: str
    admin_distance: int = 1
    metric: int = 0
    vrf: Optional[str] = None
    outgoing_interface: Optional[str] = None


@dataclass
class LLDPNeighbor:
    """Сосед по LLDP."""
    local_port: str
    remote_system: str
    remote_port: str
    remote_ip: Optional[str] = None
    remote_description: str = ''
    chassis_id: Optional[str] = None


@dataclass
class DeviceTopology:
    """Топология устройства."""
    hostname: str
    interfaces: Dict[str, Interface]
    static_routes: List[StaticRoute]
    lldp_neighbors: List[LLDPNeighbor]
    vlans: Dict[int, str]  # vlan_id -> name
    management_ip: Optional[str] = None


class TopologyParser:
    """Парсер топологии из конфигураций сетевых устройств."""
    
    VENDOR_PATTERNS = {
        'cisco': [
            r'hostname\s+(\S+)',
            r'interface\s+(\S+)',
            r'ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
            r'ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
        ],
        'hp_aruba': [
            r'hostname\s+"(.+)"',
            r'interface\s+(\S+)',
            r'ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
        ],
        'huawei': [
            r'sysname\s+(\S+)',
            r'interface\s+(\S+)',
            r'ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
            r'ip\s+route-static\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
        ],
        'aruba_cx': [
            r'hostname\s+(\S+)',
            r'interface\s+(\S+)',
            r'ip\s+address\s+(\d+\.\d+\.\d+\.\d+/\d+)',
        ]
    }
    
    def __init__(self):
        self.devices: Dict[str, DeviceTopology] = {}
    
    def parse_file(self, filepath: str, vendor: Optional[str] = None) -> DeviceTopology:
        """Парсит файл конфигурации и возвращает топологию устройства."""
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Определяем вендора если не указан
        if not vendor:
            vendor = self._detect_vendor(content)
        
        # Парсим компоненты
        hostname = self._parse_hostname(content, vendor)
        interfaces = self._parse_interfaces(content, vendor)
        routes = self._parse_static_routes(content, vendor)
        neighbors = self._parse_lldp_neighbors(content, vendor)
        vlans = self._parse_vlans(content, vendor)
        mgmt_ip = self._parse_management_ip(content, vendor)
        
        device = DeviceTopology(
            hostname=hostname,
            interfaces=interfaces,
            static_routes=routes,
            lldp_neighbors=neighbors,
            vlans=vlans,
            management_ip=mgmt_ip
        )
        
        self.devices[hostname] = device
        return device
    
    def _detect_vendor(self, content: str) -> str:
        """Определяет вендора по ключевым словам."""
        content_lower = content.lower()
        
        if 'cisco' in content_lower or 'ios' in content_lower:
            return 'cisco'
        elif 'sysname' in content_lower or 'huawei' in content_lower:
            return 'huawei'
        elif 'aruba-cx' in content_lower or 'interface 1/1/1' in content_lower:
            return 'aruba_cx'
        elif 'hostname "' in content_lower or 'ip authorized-managers' in content_lower:
            return 'hp_aruba'
        else:
            return 'cisco'  # По умолчанию
    
    def _parse_hostname(self, content: str, vendor: str) -> str:
        """Извлекает hostname."""
        patterns = {
            'cisco': r'hostname\s+(\S+)',
            'huawei': r'sysname\s+(\S+)',
            'hp_aruba': r'hostname\s+"(.+)"',
            'aruba_cx': r'hostname\s+(\S+)',
        }
        
        pattern = patterns.get(vendor, patterns['cisco'])
        match = re.search(pattern, content, re.IGNORECASE)
        return match.group(1) if match else 'unknown'
    
    def _parse_interfaces(self, content: str, vendor: str) -> Dict[str, Interface]:
        """Извлекает интерфейсы с IP-адресами."""
        interfaces = {}
        
        # Разбиваем на блоки интерфейсов
        if vendor in ['cisco', 'huawei']:
            blocks = re.findall(
                r'interface\s+(\S+)\s*\n((?:(?!interface\s+\S+).*)*)',
                content,
                re.DOTALL | re.IGNORECASE
            )
            
            for name, block in blocks:
                iface = self._parse_interface_block_cisco(name, block)
                interfaces[name] = iface
                
        elif vendor == 'hp_aruba':
            # HP имеет другой формат
            blocks = re.findall(
                r'interface\s+(\S+)\s*\n((?:(?!interface\s+\S+).*)*)',
                content,
                re.DOTALL | re.IGNORECASE
            )
            
            for name, block in blocks:
                iface = self._parse_interface_block_hp(name, block)
                interfaces[name] = iface
                
        elif vendor == 'aruba_cx':
            blocks = re.findall(
                r'interface\s+(\S+)\s*\n((?:(?!interface\s+\S+).*)*)',
                content,
                re.DOTALL | re.IGNORECASE
            )
            
            for name, block in blocks:
                iface = self._parse_interface_block_aruba_cx(name, block)
                interfaces[name] = iface
        
        return interfaces
    
    def _parse_interface_block_cisco(self, name: str, block: str) -> Interface:
        """Парсит блок интерфейса Cisco."""
        iface = Interface(name=name)
        
        # IP адрес
        ip_match = re.search(
            r'ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
            block
        )
        if ip_match:
            ip = ip_match.group(1)
            mask = ip_match.group(2)
            iface.ip_address = ip
            # Вычисляем подсеть
            try:
                iface.subnet = str(ip_network(f"{ip}/{mask}", strict=False))
            except:
                iface.subnet = f"{ip}/{mask}"
        
        # VLAN
        vlan_match = re.search(r'encapsulation\s+dot1Q\s+(\d+)', block)
        if not vlan_match:
            vlan_match = re.search(r'switchport\s+access\s+vlan\s+(\d+)', block)
        if vlan_match:
            iface.vlan = int(vlan_match.group(1))
        
        # Trunk
        if 'switchport mode trunk' in block.lower():
            iface.is_trunk = True
            # Native VLAN
            native_match = re.search(r'switchport trunk native vlan\s+(\d+)', block)
            if native_match:
                iface.native_vlan = int(native_match.group(1))
            # Allowed VLANs
            allowed_match = re.search(r'switchport trunk allowed vlan\s+(.+)', block)
            if allowed_match:
                vlans_str = allowed_match.group(1)
                iface.trunk_vlans = self._parse_vlan_range(vlans_str)
        
        # Status
        if 'shutdown' in block.lower():
            iface.status = 'admin-down'
        elif 'no shutdown' in block.lower():
            iface.status = 'up'
        
        # Speed
        speed_match = re.search(r'speed\s+(\d+)', block)
        if speed_match:
            speed = speed_match.group(1)
            iface.speed = f"{speed}M"
        
        # Description
        desc_match = re.search(r'description\s+(.+)', block)
        if desc_match:
            iface.description = desc_match.group(1).strip()
        
        # LAG/Port-channel
        if 'channel-group' in block.lower():
            iface.is_lag = True
            lag_match = re.search(r'channel-group\s+(\d+)', block)
            if lag_match:
                iface.lag_members = [f"Port-channel{lag_match.group(1)}"]
        
        return iface
    
    def _parse_interface_block_hp(self, name: str, block: str) -> Interface:
        """Парсит блок интерфейса HP/Aruba."""
        iface = Interface(name=name)
        
        # IP адрес (обычно на VLAN interface)
        ip_match = re.search(
            r'ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
            block
        )
        if ip_match:
            ip = ip_match.group(1)
            mask = ip_match.group(2)
            iface.ip_address = ip
            try:
                iface.subnet = str(ip_network(f"{ip}/{mask}", strict=False))
            except:
                iface.subnet = f"{ip}/{mask}"
        
        # VLAN
        vlan_match = re.search(r'vlan\s+(\d+)', block)
        if vlan_match:
            iface.vlan = int(vlan_match.group(1))
        
        # Status
        if 'no shutdown' in block.lower():
            iface.status = 'up'
        elif 'shutdown' in block.lower():
            iface.status = 'down'
        
        # Speed
        speed_match = re.search(r'speed-duplex\s+(\S+)', block)
        if speed_match:
            iface.speed = speed_match.group(1)
        
        return iface
    
    def _parse_interface_block_aruba_cx(self, name: str, block: str) -> Interface:
        """Парсит блок интерфейса Aruba CX."""
        iface = Interface(name=name)
        
        # IP адрес в формате CIDR
        ip_match = re.search(
            r'ip\s+address\s+(\d+\.\d+\.\d+\.\d+/\d+)',
            block
        )
        if ip_match:
            cidr = ip_match.group(1)
            iface.ip_address = cidr
            try:
                iface.subnet = str(ip_network(cidr, strict=False))
            except:
                iface.subnet = cidr
        
        # VLAN
        vlan_match = re.search(r'vlan\s+(\d+)', block)
        if vlan_match:
            iface.vlan = int(vlan_match.group(1))
        
        # Status
        if 'no shutdown' in block.lower():
            iface.status = 'up'
        
        # Trunk
        if 'trunk' in block.lower():
            iface.is_trunk = True
        
        return iface
    
    def _parse_static_routes(self, content: str, vendor: str) -> List[StaticRoute]:
        """Извлекает статические маршруты."""
        routes = []
        
        if vendor == 'cisco':
            # Cisco: ip route dest mask next-hop [distance]
            pattern = r'ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+))?'
            for match in re.finditer(pattern, content):
                routes.append(StaticRoute(
                    destination=match.group(1),
                    mask=match.group(2),
                    next_hop=match.group(3),
                    admin_distance=int(match.group(4)) if match.group(4) else 1
                ))
                
        elif vendor == 'huawei':
            # Huawei: ip route-static dest mask next-hop [preference distance]
            pattern = r'ip\s+route-static\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?:\s+preference\s+(\d+))?'
            for match in re.finditer(pattern, content):
                routes.append(StaticRoute(
                    destination=match.group(1),
                    mask=match.group(2),
                    next_hop=match.group(3),
                    admin_distance=int(match.group(4)) if match.group(4) else 60
                ))
                
        elif vendor == 'aruba_cx':
            # Aruba CX: ip route dest/mask next-hop
            pattern = r'ip\s+route\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+(\d+\.\d+\.\d+\.\d+)'
            for match in re.finditer(pattern, content):
                cidr = match.group(1)
                routes.append(StaticRoute(
                    destination=cidr.split('/')[0],
                    mask=cidr.split('/')[1],
                    next_hop=match.group(2)
                ))
        
        return routes
    
    def _parse_lldp_neighbors(self, content: str, vendor: str) -> List[LLDPNeighbor]:
        """Извлекает LLDP соседей."""
        neighbors = []
        
        # Cisco LLDP
        if vendor == 'cisco':
            blocks = re.findall(
                r'System Name:\s*(\S+).*?Port ID:\s*(\S+).*?Local Intf:\s*(\S+)',
                content,
                re.DOTALL
            )
            for system, port, local in blocks:
                neighbors.append(LLDPNeighbor(
                    local_port=local,
                    remote_system=system,
                    remote_port=port
                ))
        
        return neighbors
    
    def _parse_vlans(self, content: str, vendor: str) -> Dict[int, str]:
        """Извлекает VLAN."""
        vlans = {}
        
        if vendor in ['cisco', 'hp_aruba', 'aruba_cx']:
            pattern = r'vlan\s+(\d+)\s*\n\s*name\s+(.+)'
            for match in re.finditer(pattern, content, re.IGNORECASE):
                vlan_id = int(match.group(1))
                name = match.group(2).strip().strip('"')
                vlans[vlan_id] = name
        
        elif vendor == 'huawei':
            pattern = r'vlan\s+(\d+)\s*\n\s*name\s+(.+)'
            for match in re.finditer(pattern, content, re.IGNORECASE):
                vlan_id = int(match.group(1))
                name = match.group(2).strip()
                vlans[vlan_id] = name
        
        return vlans
    
    def _parse_management_ip(self, content: str, vendor: str) -> Optional[str]:
        """Извлекает management IP."""
        # Ищем ip authorized-managers или management vlan
        pattern = r'ip\s+authorized-managers\s+(\d+\.\d+\.\d+\.\d+)'
        match = re.search(pattern, content)
        if match:
            return match.group(1)
        return None
    
    def _parse_vlan_range(self, vlans_str: str) -> List[int]:
        """Парсит строку VLAN range (1,2,3-10,20)."""
        vlans = []
        for part in vlans_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                vlans.extend(range(int(start), int(end) + 1))
            else:
                vlans.append(int(part))
        return vlans
    
    def get_topology_graph(self) -> Tuple[List[Dict], List[Dict]]:
        """Возвращает nodes и edges для визуализации топологии."""
        nodes = []
        edges = []
        
        for hostname, device in self.devices.items():
            # Узел устройства
            nodes.append({
                'id': hostname,
                'label': hostname,
                'group': 'device',
                'type': 'device',
                'title': f"Device: {hostname}\nManagement: {device.management_ip or 'N/A'}"
            })
            
            # Интерфейсы
            for iface_name, iface in device.interfaces.items():
                node_id = f"{hostname}:{iface_name}"
                nodes.append({
                    'id': node_id,
                    'label': iface_name,
                    'group': 'interface',
                    'type': 'interface',
                    'title': self._format_interface_tooltip(iface),
                    'parent': hostname
                })
                
                # Связь интерфейса с устройством
                edges.append({
                    'from': hostname,
                    'to': node_id,
                    'label': 'has',
                    'color': {'color': '#999'},
                    'dashes': True
                })
                
                # Связь с сетью
                if iface.subnet:
                    net_id = f"net:{iface.subnet}"
                    if net_id not in [n['id'] for n in nodes]:
                        nodes.append({
                            'id': net_id,
                            'label': iface.subnet,
                            'group': 'network',
                            'type': 'network'
                        })
                    edges.append({
                        'from': node_id,
                        'to': net_id,
                        'label': 'connected',
                        'color': {'color': '#00AA00'}
                    })
            
            # Статические маршруты
            for route in device.static_routes:
                route_id = f"route:{route.destination}/{route.mask}"
                nodes.append({
                    'id': route_id,
                    'label': f"{route.destination}/{route.mask}",
                    'group': 'route',
                    'type': 'route',
                    'title': f"Next-hop: {route.next_hop}\nAD: {route.admin_distance}"
                })
                edges.append({
                    'from': hostname,
                    'to': route_id,
                    'label': f"via {route.next_hop}",
                    'color': {'color': '#0066CC'},
                    'arrows': 'to'
                })
            
            # LLDP соседи
            for neighbor in device.lldp_neighbors:
                neighbor_id = f"lldp:{neighbor.remote_system}"
                if neighbor_id not in [n['id'] for n in nodes]:
                    nodes.append({
                        'id': neighbor_id,
                        'label': neighbor.remote_system,
                        'group': 'device',
                        'type': 'device'
                    })
                edges.append({
                    'from': f"{hostname}:{neighbor.local_port}",
                    'to': neighbor_id,
                    'label': f"LLDP: {neighbor.remote_port}",
                    'color': {'color': '#FF6600'},
                    'width': 2
                })
        
        return nodes, edges
    
    def _format_interface_tooltip(self, iface: Interface) -> str:
        """Форматирует tooltip для интерфейса."""
        lines = [
            f"Name: {iface.name}",
            f"IP: {iface.ip_address or 'N/A'}",
            f"Subnet: {iface.subnet or 'N/A'}",
            f"VLAN: {iface.vlan or 'N/A'}",
            f"Status: {iface.status}",
            f"Speed: {iface.speed}",
        ]
        if iface.is_trunk:
            lines.append(f"Trunk: VLANs {iface.trunk_vlans}")
        if iface.description:
            lines.append(f"Description: {iface.description}")
        return '\\n'.join(lines)


# Экспорт
__all__ = ['TopologyParser', 'Interface', 'StaticRoute', 'LLDPNeighbor', 'DeviceTopology']
