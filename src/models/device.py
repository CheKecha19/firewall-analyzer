"""
Модель сетевого устройства.
"""
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from .interface import Interface
from .route import StaticRoute
from .rule import FirewallRule


@dataclass
class NetworkDevice:
    """
    Представление сетевого устройства (роутера, файрвола).
    
    Attributes:
        id: Уникальный идентификатор устройства (например, hostname или IP management)
        vendor: Вендор устройства (cisco, juniper, huawei, usergate)
        hostname: Имя хоста устройства
        interfaces: Список сетевых интерфейсов
        static_routes: Список статических маршрутов
        acls: Словарь ACL (ключ - имя ACL, значение - список правил)
        mgmt_ip: IP-адрес для управления
    """
    id: str
    vendor: str  # 'cisco', 'juniper', 'huawei', 'usergate'
    hostname: Optional[str] = None
    interfaces: List[Interface] = field(default_factory=list)
    static_routes: List[StaticRoute] = field(default_factory=list)
    acls: Dict[str, List[FirewallRule]] = field(default_factory=dict)
    mgmt_ip: Optional[str] = None
    
    def get_interface_by_name(self, name: str) -> Optional[Interface]:
        """Возвращает интерфейс по имени."""
        for iface in self.interfaces:
            if iface.name == name:
                return iface
        return None
    
    def get_interface_by_ip(self, ip: str) -> Optional[Interface]:
        """Возвращает интерфейс по IP-адресу (с или без маски)."""
        ip_clean = ip.split('/')[0] if '/' in ip else ip
        for iface in self.interfaces:
            if iface.ip_only == ip_clean:
                return iface
        return None
    
    def get_interfaces_by_zone(self, zone: str) -> List[Interface]:
        """Возвращает список интерфейсов в зоне."""
        return [iface for iface in self.interfaces if iface.zone == zone]
    
    def find_route_for_destination(self, dest_ip: str) -> Optional[StaticRoute]:
        """
        Находит лучший маршрут для целевого IP.
        
        Возвращает маршрут с самым длинным совпадением префикса.
        """
        from ipaddress import ip_address, ip_network
        
        best_route = None
        best_prefix_len = -1
        
        try:
            dest = ip_address(dest_ip)
        except ValueError:
            return None
        
        for route in self.static_routes:
            try:
                network = ip_network(route.destination, strict=False)
                if dest in network:
                    if network.prefixlen > best_prefix_len:
                        best_prefix_len = network.prefixlen
                        best_route = route
            except ValueError:
                continue
        
        return best_route
    
    def get_connected_networks(self) -> List[str]:
        """Возвращает список напрямую подключённых сетей."""
        networks = []
        for iface in self.interfaces:
            if iface.ip_address:
                networks.append(iface.ip_address)
        return networks
    
    def __hash__(self):
        return hash(self.id)
    
    def __eq__(self, other):
        if not isinstance(other, NetworkDevice):
            return False
        return self.id == other.id
