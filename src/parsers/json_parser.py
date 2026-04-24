"""
Парсер конфигураций UserGate (JSON) с глубоким разрешением объектов.
"""
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from .base_parser import BaseParser
from ..models.endpoint import Endpoint
from ..models.service import Service
from ..models.rule import FirewallRule
from ..core.resolver import ObjectResolver, ResolvedObject


class UserGateParser(BaseParser):
    """Парсер конфигураций UserGate NGFW (JSON формат) с полным разрешением объектов."""
    
    VENDOR = "usergate"
    
    def __init__(self):
        self.objects_data: Dict = {}
        self.resolver: Optional[ObjectResolver] = None
    
    def can_parse(self, file_path: Path, content: Optional[str] = None) -> bool:
        """Проверяет, является ли файл JSON конфигурацией UserGate."""
        if file_path.suffix.lower() != '.json':
            return False
        
        try:
            if content is None:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            data = json.loads(content)
            # UserGate конфигурация имеет firewall.rules или objects
            return 'firewall' in data or 'rules' in data or 'objects' in data or 'zones' in data
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
    
    def parse(self, file_path: Path) -> List[FirewallRule]:
        """Парсит JSON файл UserGate с полным разрешением объектов."""
        content = self.read_file(file_path)
        data = json.loads(content)
        
        # Инициализация резолвера
        self.objects_data = data
        self.resolver = ObjectResolver(data)
        
        rules = []
        
        # Парсинг правил межсетевого экрана
        if 'firewall' in data and isinstance(data['firewall'], dict):
            fw_data = data['firewall']
            if 'rules' in fw_data and isinstance(fw_data['rules'], list):
                for rule_data in fw_data['rules']:
                    if self._is_allow_rule(rule_data):
                        rule = self._parse_rule(rule_data)
                        if rule:
                            rules.append(rule)
        
        # Альтернативные форматы
        if 'rules' in data and isinstance(data['rules'], list):
            for rule_data in data['rules']:
                if self._is_allow_rule(rule_data):
                    rule = self._parse_rule(rule_data)
                    if rule:
                        rules.append(rule)
        
        return rules
    
    def _is_allow_rule(self, rule_data: dict) -> bool:
        """Проверяет, является ли правило разрешающим."""
        action = rule_data.get('action', '').lower()
        return action in ['accept', 'allow', 'permit', 'pass']
    
    def _parse_rule(self, rule_data: dict) -> Optional[FirewallRule]:
        """Парсит отдельное правило с полным разрешением объектов."""
        rule_id = str(rule_data.get('id', rule_data.get('name', 'unknown')))
        name = rule_data.get('name', rule_id)
        
        # Используем резолвер для разрешения всех ссылок
        if self.resolver:
            resolved = self.resolver.resolve_rule(rule_data)
            sources = resolved['sources']
            destinations = resolved['destinations']
            services = resolved['services']
        else:
            # Fallback - базовое разрешение
            sources, destinations, services = self._basic_resolution(rule_data)
        
        # Если после разрешения нет источников/назначений, создаём any
        if not sources:
            sources = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        if not destinations:
            destinations = [Endpoint('any', 'host', {'0.0.0.0/0'})]
        if not services:
            services = [Service('any', 'ip', set())]
        
        # Статус
        enabled = rule_data.get('enabled', True)
        if isinstance(enabled, str):
            enabled = enabled.lower() in ['true', 'yes', '1', 'on']
        
        return FirewallRule(
            name=name,
            rule_id=rule_id,
            sources=sources,
            destinations=destinations,
            services=services,
            action=rule_data.get('action', 'accept'),
            enabled=enabled,
            description=rule_data.get('description'),
            vendor=self.VENDOR
        )
    
    def _basic_resolution(self, rule_data: dict) -> Tuple[List[Endpoint], List[Endpoint], List[Service]]:
        """Базовое разрешение без полной рекурсии (fallback)."""
        sources = []
        destinations = []
        services = []
        
        # Источники
        src_refs = rule_data.get('src', rule_data.get('source', []))
        for src_ref in src_refs if isinstance(src_refs, list) else [src_refs]:
            endpoint = self._resolve_basic_endpoint(src_ref)
            if endpoint:
                sources.append(endpoint)
        
        # Назначения
        dst_refs = rule_data.get('dst', rule_data.get('destination', []))
        for dst_ref in dst_refs if isinstance(dst_refs, list) else [dst_refs]:
            endpoint = self._resolve_basic_endpoint(dst_ref)
            if endpoint:
                destinations.append(endpoint)
        
        # Сервисы
        svc_refs = rule_data.get('service', [])
        for svc_ref in svc_refs if isinstance(svc_refs, list) else [svc_refs]:
            service = self._resolve_basic_service(svc_ref)
            if service:
                services.append(service)
        
        return sources, destinations, services
    
    def _resolve_basic_endpoint(self, ref: dict or str) -> Optional[Endpoint]:
        """Базовое разрешение endpoint (fallback)."""
        if isinstance(ref, dict):
            ref_id = ref.get('id') or ref.get('name')
            ref_type = ref.get('type', 'unknown')
        else:
            ref_id = ref
            ref_type = 'unknown'
        
        if not ref_id:
            return None
        
        # Проверяем, является ли IP
        if self._is_ip_or_subnet(ref_id):
            if '/' in ref_id:
                return Endpoint(ref_id, 'subnet', {ref_id})
            else:
                return Endpoint(ref_id, 'host', {f"{ref_id}/32"})
        
        # Ищем в объектах
        zones = self.objects_data.get('zones', [])
        for zone in zones:
            if zone.get('id') == ref_id or zone.get('name') == ref_id:
                return Endpoint(
                    zone.get('name', ref_id),
                    'zone',
                    zone=zone.get('name', ref_id)
                )
        
        # IP-списки
        if 'objects' in self.objects_data and 'ip_lists' in self.objects_data['objects']:
            for ip_list in self.objects_data['objects']['ip_lists']:
                if ip_list.get('id') == ref_id or ip_list.get('name') == ref_id:
                    cidrs = set()
                    content = ip_list.get('content', [])
                    for item in content:
                        if isinstance(item, dict):
                            ip = item.get('ip') or item.get('subnet')
                            if ip:
                                cidrs.add(ip)
                        elif isinstance(item, str):
                            cidrs.add(item)
                    
                    return Endpoint(
                        ip_list.get('name', ref_id),
                        'group' if len(cidrs) > 1 else 'subnet',
                        cidrs=cidrs,
                        description=ip_list.get('description')
                    )
        
        return Endpoint(str(ref_id), 'unknown', set())
    
    def _resolve_basic_service(self, ref: dict or str) -> Optional[Service]:
        """Базовое разрешение сервиса (fallback)."""
        if isinstance(ref, dict):
            ref_id = ref.get('id') or ref.get('name')
            protocol = ref.get('protocol', 'tcp')
            ports = ref.get('ports', ref.get('port', []))
        else:
            ref_id = ref
            # Ищем в сервисах
            if 'objects' in self.objects_data and 'services' in self.objects_data['objects']:
                for svc in self.objects_data['objects']['services']:
                    if svc.get('id') == ref or svc.get('name') == ref:
                        protocol = svc.get('protocol', 'tcp')
                        ports_data = svc.get('ports', [])
                        ports = [str(p) for p in ports_data] if isinstance(ports_data, list) else [str(ports_data)]
                        return Service(
                            svc.get('name', ref),
                            protocol,
                            set(ports) if ports else set()
                        )
            # Парсим из строки
            protocol, ports = self._parse_service_string(ref)
        
        if isinstance(ports, (list, tuple)):
            ports_set = set(str(p) for p in ports)
        elif ports:
            ports_set = {str(ports)}
        else:
            ports_set = set()
        
        return Service(str(ref_id), protocol, ports_set)
    
    def _is_ip_or_subnet(self, s: str) -> bool:
        """Проверяет, является ли строка IP или подсетью."""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
        return bool(re.match(ip_pattern, s))
    
    def _parse_service_string(self, s: str) -> Tuple[str, Set[str]]:
        """Парсит строку сервиса типа 'tcp/80'."""
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
            'icmp': ('icmp', set()),
            'any': ('ip', set()),
        }
        
        s_lower = s.lower()
        if s_lower in predefined:
            return predefined[s_lower]
        
        if '/' in s:
            parts = s.split('/')
            return parts[0], {parts[1]}
        
        return 'tcp', {s}
    
    def parse_topology(self, file_path: Path) -> Tuple[List[Interface], List[StaticRoute]]:
        """
        Парсит топологию (интерфейсы и маршруты) из JSON UserGate.
        
        Returns:
            Tuple (list of Interface, list of StaticRoute)
        """
        from ..models.interface import Interface
        from ..models.route import StaticRoute
        
        interfaces = []
        routes = []
        
        try:
            content = self.read_file(file_path)
            data = json.loads(content)
            
            # Парсим интерфейсы
            if 'interfaces' in data and isinstance(data['interfaces'], list):
                for iface_data in data['interfaces']:
                    name = iface_data.get('name', iface_data.get('id'))
                    ip = iface_data.get('ip')
                    mask = iface_data.get('mask')
                    zone = iface_data.get('zone')
                    description = iface_data.get('description')
                    enabled = iface_data.get('enabled', True)
                    
                    ip_cidr = None
                    if ip and mask:
                        try:
                            from ipaddress import IPv4Network
                            network = IPv4Network(f'{ip}/{mask}', strict=False)
                            ip_cidr = str(network)
                        except:
                            ip_cidr = f'{ip}/24'
                    
                    interfaces.append(Interface(
                        name=name,
                        ip_address=ip_cidr,
                        zone=zone,
                        description=description,
                        enabled=enabled
                    ))
            
            # Парсим маршруты
            if 'routes' in data and isinstance(data['routes'], list):
                for route_data in data['routes']:
                    dest = route_data.get('destination')
                    next_hop = route_data.get('gateway') or route_data.get('next_hop')
                    distance = route_data.get('distance', 1)
                    
                    if dest and next_hop:
                        routes.append(StaticRoute(
                            destination=dest,
                            next_hop=next_hop,
                            admin_distance=distance
                        ))
            
            # Альтернативный формат: routing.static
            if 'routing' in data and isinstance(data['routing'], dict):
                routing = data['routing']
                if 'static' in routing and isinstance(routing['static'], list):
                    for route_data in routing['static']:
                        dest = route_data.get('destination') or route_data.get('network')
                        next_hop = route_data.get('next_hop') or route_data.get('gateway')
                        distance = route_data.get('admin_distance', 1)
                        
                        if dest and next_hop:
                            routes.append(StaticRoute(
                                destination=dest,
                                next_hop=next_hop,
                                admin_distance=distance
                            ))
                        
        except (json.JSONDecodeError, Exception):
            pass  # При ошибке возвращаем пустые списки
        
        return interfaces, routes
