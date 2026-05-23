"""
Модуль глубокого разрешения объектов UserGate.
Рекурсивно раскрывает группы, диапазоны и списки до конечных IP/подсетей и портов.
"""
import ipaddress
from typing import Dict, List, Set, Optional, Union, Any
from dataclasses import dataclass, field
from ..models.endpoint import Endpoint
from ..models.service import Service


@dataclass
class ResolvedObject:
    """Результат разрешения объекта."""
    endpoints: List[Endpoint] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    
    def merge(self, other: 'ResolvedObject'):
        """Объединяет с другим результатом."""
        self.endpoints.extend(other.endpoints)
        self.services.extend(other.services)


class ObjectResolver:
    """
    Рекурсивный резолвер объектов UserGate.
    Раскрывает вложенные группы, диапазоны адресов и портов.
    """
    
    def __init__(self, objects_data: Dict[str, Any]):
        """
        Args:
            objects_data: Словарь с объектами из JSON UserGate
        """
        self.objects = objects_data
        self.cache: Dict[str, ResolvedObject] = {}
        
        # Индексы для быстрого поиска
        self._ip_lists: Dict[str, Any] = {}
        self._services: Dict[str, Any] = {}
        self._network_groups: Dict[str, Any] = {}
        self._service_groups: Dict[str, Any] = {}
        self._zones: Dict[str, Any] = {}
        self._address_ranges: Dict[str, Any] = {}
        
        self._build_indexes()
    
    def _build_indexes(self):
        """Строит индексы для быстрого поиска объектов."""
        if 'objects' in self.objects:
            objects = self.objects['objects']
            
            if 'ip_lists' in objects:
                for item in objects['ip_lists']:
                    key = item.get('id') or item.get('name')
                    if key:
                        self._ip_lists[key] = item
            
            if 'services' in objects:
                for item in objects['services']:
                    key = item.get('id') or item.get('name')
                    if key:
                        self._services[key] = item
            
            if 'network_groups' in objects:
                for item in objects['network_groups']:
                    key = item.get('id') or item.get('name')
                    if key:
                        self._network_groups[key] = item
            
            if 'service_groups' in objects:
                for item in objects['service_groups']:
                    key = item.get('id') or item.get('name')
                    if key:
                        self._service_groups[key] = item
            
            if 'zones' in objects:
                for item in objects['zones']:
                    key = item.get('id') or item.get('name')
                    if key:
                        self._zones[key] = item
            
            if 'address_ranges' in objects:
                for item in objects['address_ranges']:
                    key = item.get('id') or item.get('name')
                    if key:
                        self._address_ranges[key] = item
        
        # Зоны могут быть и в корне
        if 'zones' in self.objects:
            for item in self.objects['zones']:
                key = item.get('id') or item.get('name')
                if key:
                    self._zones[key] = item
    
    def resolve(self, obj_ref: Union[str, Dict[str, Any]], obj_type: str = 'auto') -> ResolvedObject:
        """
        Рекурсивно разрешает объект.
        
        Args:
            obj_ref: Ссылка на объект (ID, имя или словарь)
            obj_type: Тип объекта ('ip', 'service', 'zone', 'auto')
            
        Returns:
            ResolvedObject с раскрытыми endpoints и services
        """
        # Извлекаем ID
        if isinstance(obj_ref, dict):
            obj_id = obj_ref.get('id') or obj_ref.get('name')
            obj_type = obj_ref.get('type', obj_type)
        else:
            obj_id = str(obj_ref)
        
        if not obj_id:
            return ResolvedObject()
        
        # Проверяем кэш
        cache_key = f"{obj_type}:{obj_id}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        result = ResolvedObject()
        
        # Определяем тип и разрешаем
        if obj_type == 'auto':
            # Пытаемся определить тип по наличию в индексах
            if obj_id in self._zones:
                result = self._resolve_zone(obj_id)
            elif obj_id in self._network_groups:
                result = self._resolve_network_group(obj_id)
            elif obj_id in self._ip_lists:
                result = self._resolve_ip_list(obj_id)
            elif obj_id in self._address_ranges:
                result = self._resolve_address_range(obj_id)
            elif obj_id in self._service_groups:
                result = self._resolve_service_group(obj_id)
            elif obj_id in self._services:
                result = self._resolve_service(obj_id)
            else:
                # Пробуем как IP или CIDR
                result = self._resolve_as_ip(obj_id)
        
        elif obj_type in ['zone', 'network', 'subnet', 'host', 'group', 'unknown']:
            if obj_id in self._zones:
                result = self._resolve_zone(obj_id)
            elif obj_id in self._network_groups:
                result = self._resolve_network_group(obj_id)
            elif obj_id in self._ip_lists:
                result = self._resolve_ip_list(obj_id)
            elif obj_id in self._address_ranges:
                result = self._resolve_address_range(obj_id)
            else:
                # Пробуем как IP
                result = self._resolve_as_ip(obj_id)
        
        elif obj_type == 'service':
            if obj_id in self._service_groups:
                result = self._resolve_service_group(obj_id)
            elif obj_id in self._services:
                result = self._resolve_service(obj_id)
            else:
                result = self._resolve_as_service(obj_id)
        
        # Кэшируем результат
        self.cache[cache_key] = result
        return result
    
    def _resolve_zone(self, zone_id: str) -> ResolvedObject:
        """Разрешает зону в список сетей."""
        zone = self._zones.get(zone_id, {})
        result = ResolvedObject()
        
        # Зона ссылается на network_groups или ip_lists
        networks = zone.get('networks', [])
        for net_ref in networks if isinstance(networks, list) else [networks]:
            net_id = net_ref.get('id') if isinstance(net_ref, dict) else net_ref
            if net_id:
                if net_id in self._network_groups:
                    resolved = self._resolve_network_group(net_id)
                    result.merge(resolved)
                elif net_id in self._ip_lists:
                    resolved = self._resolve_ip_list(net_id)
                    result.merge(resolved)
        
        # Если зона не имеет сетей, создаём endpoint саму зону
        if not result.endpoints:
            zone_name = zone.get('name', zone_id)
            result.endpoints.append(Endpoint(
                name=zone_name,
                endpoint_type='zone',
                zone=zone_name,
                cidrs=set()
            ))
        
        return result
    
    def _resolve_network_group(self, group_id: str) -> ResolvedObject:
        """Рекурсивно разрешает группу сетей."""
        group = self._network_groups.get(group_id, {})
        result = ResolvedObject()
        
        members = group.get('members', [])
        for member in members if isinstance(members, list) else [members]:
            member_id = member.get('id') if isinstance(member, dict) else member
            member_type = member.get('type') if isinstance(member, dict) else 'auto'
            
            if not member_id:
                continue
            
            # Рекурсивное разрешение
            if member_id in self._network_groups and member_id != group_id:  # Избегаем циклов
                resolved = self._resolve_network_group(member_id)
                result.merge(resolved)
            elif member_id in self._ip_lists:
                resolved = self._resolve_ip_list(member_id)
                result.merge(resolved)
            elif member_id in self._address_ranges:
                resolved = self._resolve_address_range(member_id)
                result.merge(resolved)
            else:
                # Пробуем как IP
                resolved = self._resolve_as_ip(member_id)
                result.merge(resolved)
        
        return result
    
    def _resolve_ip_list(self, list_id: str) -> ResolvedObject:
        """Разрешает список IP-адресов."""
        ip_list = self._ip_lists.get(list_id, {})
        result = ResolvedObject()
        
        content = ip_list.get('content', [])
        cidrs = set()
        
        for item in content if isinstance(content, list) else [content]:
            if isinstance(item, dict):
                ip = item.get('ip') or item.get('subnet') or item.get('address')
                if ip:
                    cidrs.add(self._normalize_ip(ip))
            elif isinstance(item, str):
                cidrs.add(self._normalize_ip(item))
        
        if cidrs:
            result.endpoints.append(Endpoint(
                name=ip_list.get('name', list_id),
                endpoint_type='subnet' if len(cidrs) > 1 else 'host',
                cidrs=cidrs,
                description=ip_list.get('description')
            ))
        
        return result
    
    def _resolve_address_range(self, range_id: str) -> ResolvedObject:
        """Разрешает диапазон адресов в список /24 подсетей."""
        addr_range = self._address_ranges.get(range_id, {})
        result = ResolvedObject()
        
        start_ip = addr_range.get('start_ip') or addr_range.get('start')
        end_ip = addr_range.get('end_ip') or addr_range.get('end')
        
        if start_ip and end_ip:
            try:
                # Конвертируем диапазон в сети
                networks = self._range_to_networks(start_ip, end_ip)
                cidrs = {str(net) for net in networks}
                
                result.endpoints.append(Endpoint(
                    name=addr_range.get('name', range_id),
                    endpoint_type='subnet',
                    cidrs=cidrs,
                    description=f"Range {start_ip}-{end_ip}"
                ))
            except (ValueError, TypeError):
                pass
        
        return result
    
    def _resolve_service_group(self, group_id: str) -> ResolvedObject:
        """Рекурсивно разрешает группу сервисов."""
        group = self._service_groups.get(group_id, {})
        result = ResolvedObject()
        
        members = group.get('members', [])
        for member in members if isinstance(members, list) else [members]:
            member_id = member.get('id') if isinstance(member, dict) else member
            
            if not member_id:
                continue
            
            if member_id in self._service_groups and member_id != group_id:
                resolved = self._resolve_service_group(member_id)
                result.merge(resolved)
            elif member_id in self._services:
                resolved = self._resolve_service(member_id)
                result.merge(resolved)
            else:
                # Пробуем распарсить как строку сервиса
                resolved = self._resolve_as_service(member_id)
                result.merge(resolved)
        
        return result
    
    def _resolve_service(self, service_id: str) -> ResolvedObject:
        """Разрешает сервис с поддержкой диапазонов портов."""
        service = self._services.get(service_id, {})
        result = ResolvedObject()
        
        protocol = service.get('protocol', 'tcp').lower()
        ports_data = service.get('ports', [])
        ports = set()
        
        # Обрабатываем порты
        for port in ports_data if isinstance(ports_data, list) else [ports_data]:
            if isinstance(port, dict):
                # Диапазон портов
                port_start = port.get('start') or port.get('from')
                port_end = port.get('end') or port.get('to')
                if port_start and port_end:
                    ports.add(f"{port_start}-{port_end}")
                elif port_start:
                    ports.add(str(port_start))
            elif isinstance(port, (int, str)):
                ports.add(str(port))
        
        result.services.append(Service(
            name=service.get('name', service_id),
            protocol=protocol,
            ports=ports,
            description=service.get('description')
        ))
        
        return result
    
    def _resolve_as_ip(self, ip_string: str) -> ResolvedObject:
        """Пробует интерпретировать строку как IP или CIDR."""
        result = ResolvedObject()
        
        try:
            normalized = self._normalize_ip(ip_string)
            if '/' in normalized:
                # Подсеть
                result.endpoints.append(Endpoint(
                    name=normalized,
                    endpoint_type='subnet',
                    cidrs={normalized}
                ))
            else:
                # Хост
                result.endpoints.append(Endpoint(
                    name=normalized,
                    endpoint_type='host',
                    cidrs={f"{normalized}/32"}
                ))
        except ValueError:
            # Не IP, создаём endpoint с именем
            result.endpoints.append(Endpoint(
                name=ip_string,
                endpoint_type='unknown',
                cidrs=set()
            ))
        
        return result
    
    def _resolve_as_service(self, svc_string: str) -> ResolvedObject:
        """Пробует распарсить строку как сервис."""
        result = ResolvedObject()
        
        # Предопределённые сервисы
        predefined = {
            'http': ('tcp', {'80'}),
            'https': ('tcp', {'443'}),
            'ssh': ('tcp', {'22'}),
            'telnet': ('tcp', {'23'}),
            'ftp': ('tcp', {'21'}),
            'dns': ('udp', {'53'}),
            'ntp': ('udp', {'123'}),
            'smtp': ('tcp', {'25'}),
            'pop3': ('tcp', {'110'}),
            'imap': ('tcp', {'143'}),
            'ldap': ('tcp', {'389'}),
            'ldaps': ('tcp', {'636'}),
            'kerberos': ('tcp', {'88'}),
            'snmp': ('udp', {'161'}),
            'icmp': ('icmp', set()),
            'any': ('ip', set()),
        }
        
        svc_lower = svc_string.lower()
        if svc_lower in predefined:
            proto, ports = predefined[svc_lower]
            result.services.append(Service(
                name=svc_string,
                protocol=proto,
                ports=ports
            ))
        elif '/' in svc_string:
            # Формат tcp/80 или udp/53-54
            parts = svc_string.split('/')
            if len(parts) == 2:
                proto = parts[0].lower()
                port_spec = parts[1]
                result.services.append(Service(
                    name=svc_string,
                    protocol=proto,
                    ports={port_spec}
                ))
        else:
            # Неизвестный сервис
            result.services.append(Service(
                name=svc_string,
                protocol='tcp',
                ports={svc_string}
            ))
        
        return result
    
    def _normalize_ip(self, ip: str) -> str:
        """Нормализует IP-адрес или подсеть."""
        ip = ip.strip()
        
        if '/' in ip:
            # Уже CIDR
            network = ipaddress.ip_network(ip, strict=False)
            return str(network)
        else:
            # Проверяем, является ли IP
            try:
                ipaddress.ip_address(ip)
                return ip
            except ValueError:
                # Пробуем как сеть с маской
                if ' ' in ip:
                    parts = ip.split()
                    if len(parts) == 2:
                        return self._wildcard_to_cidr(parts[0], parts[1])
                raise
    
    def _wildcard_to_cidr(self, ip: str, wildcard: str) -> str:
        """Конвертирует wildcard mask в CIDR."""
        try:
            parts = wildcard.split('.')
            if len(parts) != 4:
                return f"{ip}/32"
            
            mask = 0
            for part in parts:
                mask = (mask << 8) | (255 - int(part))
            
            # Считаем биты
            bits = bin(mask).count('1')
            return f"{ip}/{bits}"
        except (ValueError, AttributeError):
            return f"{ip}/32"
    
    def _range_to_networks(self, start_ip: str, end_ip: str) -> List[ipaddress.IPv4Network]:
        """Конвертирует диапазон IP в список сетей."""
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        
        # Используем summarize_address_range
        networks = list(ipaddress.summarize_address_range(start, end))
        return networks
    
    def resolve_rule(self, rule_data: Dict[str, Any]) -> Dict[str, List]:
        """
        Разрешает все ссылки в правиле.
        
        Args:
            rule_data: Данные правила из JSON
            
        Returns:
            Словарь с 'sources', 'destinations', 'services'
        """
        result = {
            'sources': [],
            'destinations': [],
            'services': []
        }
        
        # Источники
        src_refs = rule_data.get('src', rule_data.get('source', []))
        for src_ref in src_refs if isinstance(src_refs, list) else [src_refs]:
            resolved = self.resolve(src_ref, 'network')
            result['sources'].extend(resolved.endpoints)
        
        # Назначения
        dst_refs = rule_data.get('dst', rule_data.get('destination', []))
        for dst_ref in dst_refs if isinstance(dst_refs, list) else [dst_refs]:
            resolved = self.resolve(dst_ref, 'network')
            result['destinations'].extend(resolved.endpoints)
        
        # Сервисы
        svc_refs = rule_data.get('service', [])
        for svc_ref in svc_refs if isinstance(svc_refs, list) else [svc_refs]:
            resolved = self.resolve(svc_ref, 'service')
            result['services'].extend(resolved.services)
        
        return result
