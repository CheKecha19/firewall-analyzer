"""
Проверка достижимости с учётом ACL и топологии сети.
"""
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import networkx as nx

from ..models.rule import FirewallRule
from ..models.device import NetworkDevice
from ..models.interface import Interface
from ..models.route import StaticRoute
from .topology_builder import TopologyBuilder


class PathStatus(Enum):
    """Статус прохождения пути."""
    ALLOW = "allow"
    DENY = "deny"
    NO_ROUTE = "no_route"
    UNKNOWN = "unknown"


@dataclass
class PathHop:
    """Представление одного "перехода" в пути."""
    device_id: str
    ingress_iface: Optional[str]
    egress_iface: Optional[str]
    action: str  # allow, deny, forward
    matched_rule: Optional[str] = None
    message: str = ""


@dataclass
class ReachabilityResult:
    """Результат проверки достижимости."""
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    status: PathStatus
    path: List[PathHop] = field(default_factory=list)
    message: str = ""
    
    @property
    def is_reachable(self) -> bool:
        """Возвращает True, если путь доступен."""
        return self.status == PathStatus.ALLOW
    
    @property
    def blocking_device(self) -> Optional[str]:
        """Возвращает устройство, которое блокирует трафик."""
        for hop in reversed(self.path):
            if hop.action == "deny":
                return hop.device_id
        return None


class ReachabilityChecker:
    """Проверяет достижимость между IP-адресами с учётом ACL."""
    
    def __init__(self, topology_builder: TopologyBuilder, rules: List[FirewallRule]):
        """
        Args:
            topology_builder: Построитель топологии сети
            rules: Список всех правил firewall (для поиска ACL)
        """
        self.topology = topology_builder
        self.rules = rules
        self._rules_by_acl: Dict[str, List[FirewallRule]] = {}
        self._build_acl_index()
    
    def _build_acl_index(self):
        """Индексирует правила по имени ACL."""
        for rule in self.rules:
            # Предполагаем, что имя ACL может быть в метаданных
            acl_name = getattr(rule, 'acl_name', None) or rule.name.split('_')[0]
            if acl_name:
                if acl_name not in self._rules_by_acl:
                    self._rules_by_acl[acl_name] = []
                self._rules_by_acl[acl_name].append(rule)
    
    def check_reachability(
        self,
        source_ip: str,
        dest_ip: str,
        dest_port: int = 80,
        protocol: str = "tcp",
        source_port: int = 0
    ) -> ReachabilityResult:
        """
        Проверяет достижимость от source_ip до dest_ip.
        
        Returns:
            ReachabilityResult с деталями пути
        """
        result = ReachabilityResult(
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol=protocol,
            status=PathStatus.UNKNOWN
        )
        
        # Находим исходное устройство
        source_device = self._find_device_by_ip(source_ip)
        if not source_device:
            result.status = PathStatus.NO_ROUTE
            result.message = f"No device found for source IP {source_ip}"
            return result
        
        # Начинаем трассировку
        visited_devices: Set[str] = set()
        current_device = source_device
        current_ip = source_ip
        
        while current_device:
            if current_device.id in visited_devices:
                result.status = PathStatus.UNKNOWN
                result.message = "Routing loop detected"
                return result
            
            visited_devices.add(current_device.id)
            
            # Находим исходящий интерфейс для destination
            route = current_device.find_route_for_destination(dest_ip)
            if not route:
                result.status = PathStatus.NO_ROUTE
                result.message = f"No route to {dest_ip} on device {current_device.id}"
                return result
            
            # Находим исходящий интерфейс
            egress_iface = self._get_egress_interface(current_device, route)
            ingress_iface = self._get_ingress_interface(current_device, current_ip)
            
            # Проверяем ACL на исходящем интерфейсе
            acl_check = self._check_acl(
                current_device,
                ingress_iface,
                egress_iface,
                source_ip,
                dest_ip,
                dest_port,
                protocol
            )
            
            hop = PathHop(
                device_id=current_device.id,
                ingress_iface=ingress_iface.name if ingress_iface else None,
                egress_iface=egress_iface.name if egress_iface else None,
                action=acl_check[0],
                matched_rule=acl_check[1],
                message=acl_check[2]
            )
            result.path.append(hop)
            
            if acl_check[0] == "deny":
                result.status = PathStatus.DENY
                result.message = f"Access denied by {current_device.id}"
                return result
            
            # Переходим к следующему устройству
            next_device = self._get_next_hop_device(current_device, route)
            if not next_device:
                # Проверяем, достигли ли мы целевой сети
                if self._is_in_network(dest_ip, route.destination):
                    result.status = PathStatus.ALLOW
                    result.message = f"Destination {dest_ip} reachable"
                    return result
                else:
                    result.status = PathStatus.NO_ROUTE
                    result.message = f"Next hop unreachable for {dest_ip}"
                    return result
            
            current_device = next_device
            current_ip = self._get_device_ip(current_device)
        
        result.status = PathStatus.UNKNOWN
        result.message = "Path analysis incomplete"
        return result
    
    def _find_device_by_ip(self, ip: str) -> Optional[NetworkDevice]:
        """Находит устройство, содержащее IP-адрес в интерфейсах."""
        try:
            target_ip = ipaddress.ip_address(ip)
        except ValueError:
            return None
        
        for device_id, device in self.topology.devices.items():
            for iface in device.interfaces:
                if iface.ip_address:
                    try:
                        network = ipaddress.ip_network(iface.ip_address, strict=False)
                        if target_ip in network:
                            return device
                    except ValueError:
                        continue
        return None
    
    def _get_egress_interface(self, device: NetworkDevice, route: StaticRoute) -> Optional[Interface]:
        """Находит исходящий интерфейс для маршрута."""
        if route.is_via_interface:
            return device.get_interface_by_name(route.outgoing_interface)
        
        # Иначе ищем по next-hop IP
        if route.next_hop_ip:
            for iface in device.interfaces:
                if iface.ip_address:
                    try:
                        network = ipaddress.ip_network(iface.ip_address, strict=False)
                        if ipaddress.ip_address(route.next_hop_ip) in network:
                            return iface
                    except ValueError:
                        continue
        return None
    
    def _get_ingress_interface(self, device: NetworkDevice, src_ip: str) -> Optional[Interface]:
        """Находит входящий интерфейс по IP-адресу источника."""
        try:
            target_ip = ipaddress.ip_address(src_ip)
        except ValueError:
            return None
        
        for iface in device.interfaces:
            if iface.ip_address:
                try:
                    network = ipaddress.ip_network(iface.ip_address, strict=False)
                    if target_ip in network:
                        return iface
                except ValueError:
                    continue
        return None
    
    def _check_acl(
        self,
        device: NetworkDevice,
        ingress_iface: Optional[Interface],
        egress_iface: Optional[Interface],
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str
    ) -> Tuple[str, Optional[str], str]:
        """
        Проверяет ACL для пакета.
        
        Returns:
            Tuple (action, matched_rule_name, message)
        """
        # Получаем ACL для исходящего интерфейса
        acl_name = None
        if egress_iface and egress_iface.acl_out:
            acl_name = egress_iface.acl_out
        elif ingress_iface and ingress_iface.acl_in:
            acl_name = ingress_iface.acl_in
        
        if not acl_name:
            # Нет ACL - разрешаем по умолчанию
            return ("allow", None, "No ACL applied")
        
        # Ищем правила для этого ACL
        acl_rules = self._rules_by_acl.get(acl_name, [])
        if not acl_rules:
            return ("allow", None, f"ACL {acl_name} not found in rules")
        
        # Проверяем правила по порядку
        for rule in acl_rules:
            if self._rule_matches(rule, src_ip, dst_ip, dst_port, protocol):
                action = rule.action.lower()
                if action in ("deny", "drop"):
                    return ("deny", rule.name, f"Denied by rule {rule.name}")
                elif action in ("accept", "allow", "permit"):
                    return ("allow", rule.name, f"Allowed by rule {rule.name}")
        
        # Ни одно правило не сработало - implicit deny
        return ("deny", None, "Implicit deny (no matching rule)")
    
    def _rule_matches(
        self,
        rule: FirewallRule,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str
    ) -> bool:
        """Проверяет, соответствует ли пакет правилу."""
        # Проверяем источник
        src_match = False
        for src in rule.sources:
            if self._ip_in_endpoint(src_ip, src.name):
                src_match = True
                break
        if not src_match:
            return False
        
        # Проверяем назначение
        dst_match = False
        for dst in rule.destinations:
            if self._ip_in_endpoint(dst_ip, dst.name):
                dst_match = True
                break
        if not dst_match:
            return False
        
        # Проверяем порт (если указан в правиле)
        if rule.services:
            port_match = False
            for svc in rule.services:
                if str(dst_port) in svc.ports or svc.name.lower() == "any":
                    port_match = True
                    break
            if not port_match:
                return False
        
        return True
    
    def _ip_in_endpoint(self, ip: str, endpoint: str) -> bool:
        """Проверяет, находится ли IP в endpoint (IP, сеть, any)."""
        if endpoint.lower() == "any":
            return True
        
        try:
            target_ip = ipaddress.ip_address(ip)
            
            # Проверяем как сеть
            if "/" in endpoint:
                network = ipaddress.ip_network(endpoint, strict=False)
                return target_ip in network
            
            # Проверяем как IP
            return str(target_ip) == endpoint
        except ValueError:
            return False
    
    def _get_next_hop_device(self, current_device: NetworkDevice, route: StaticRoute) -> Optional[NetworkDevice]:
        """Находит следующее устройство по маршруту."""
        if not route.next_hop_ip:
            return None
        
        # Ищем устройство, которое имеет этот IP на интерфейсе
        for device_id, device in self.topology.devices.items():
            if device_id == current_device.id:
                continue
            
            for iface in device.interfaces:
                if iface.ip_only == route.next_hop_ip:
                    return device
        
        return None
    
    def _is_in_network(self, ip: str, network_cidr: str) -> bool:
        """Проверяет, находится ли IP в сети CIDR."""
        try:
            target_ip = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(network_cidr, strict=False)
            return target_ip in network
        except ValueError:
            return False
    
    def _get_device_ip(self, device: NetworkDevice) -> str:
        """Возвращает IP-адрес устройства (management IP или первый интерфейс)."""
        if device.mgmt_ip:
            return device.mgmt_ip
        
        for iface in device.interfaces:
            if iface.ip_only:
                return iface.ip_only
        
        return "0.0.0.0"
    
    def get_shortest_path_devices(
        self,
        source_ip: str,
        dest_ip: str
    ) -> List[str]:
        """Возвращает список устройств на кратчайшем пути (по топологии)."""
        source_device = self._find_device_by_ip(source_ip)
        dest_device = self._find_device_by_ip(dest_ip)
        
        if not source_device or not dest_device:
            return []
        
        if self.topology.topology_graph is None:
            self.topology.build_topology_graph()
        
        try:
            path = nx.shortest_path(
                self.topology.topology_graph,
                source_device.id,
                dest_device.id
            )
            return path
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []
