"""
Security Zone Topology Builder
Строит топологию зон безопасности и проверяет межзоновые политики.
"""

import re
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class SecurityZone:
    """Security Zone (Inside, Outside, DMZ и т.д.)."""
    name: str
    security_level: int = 0  # 0-100, выше = безопаснее
    interfaces: List[str] = field(default_factory=list)
    description: str = ''
    color: str = '#90EE90'


@dataclass
class ZonePolicy:
    """Политика между зонами."""
    from_zone: str
    to_zone: str
    action: str  # permit/deny/inspect
    services: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    rules_count: int = 0


@dataclass
class ZoneViolation:
    """Нарушение политики зон."""
    from_zone: str
    to_zone: str
    severity: str  # critical/high/medium/low
    description: str
    recommendation: str


class SecurityZoneBuilder:
    """Строитель топологии зон безопасности."""
    
    # Предопределённые зоны и их уровни безопасности
    DEFAULT_ZONES = {
        'outside': {'level': 0, 'color': '#FF6B6B', 'name': 'Outside'},
        'untrust': {'level': 0, 'color': '#FF6B6B', 'name': 'Untrust'},
        'dmz': {'level': 50, 'color': '#FFA07A', 'name': 'DMZ'},
        'inside': {'level': 100, 'color': '#4ECDC4', 'name': 'Inside'},
        'trust': {'level': 100, 'color': '#4ECDC4', 'name': 'Trust'},
        'management': {'level': 100, 'color': '#45B7D1', 'name': 'Management'},
        'guest': {'level': 25, 'color': '#F7DC6F', 'name': 'Guest'},
    }
    
    # Рискованные направления
    HIGH_RISK_FLOWS = [
        ('outside', 'inside'),
        ('outside', 'management'),
        ('dmz', 'inside'),
        ('dmz', 'management'),
        ('guest', 'inside'),
        ('untrust', 'trust'),
    ]
    
    def __init__(self):
        self.zones: Dict[str, SecurityZone] = {}
        self.policies: List[ZonePolicy] = []
        self.violations: List[ZoneViolation] = []
    
    def add_zone(self, name: str, security_level: int = None, 
                 interfaces: List[str] = None, description: str = ''):
        """Добавляет зону."""
        name_lower = name.lower()
        
        # Используем предопределённые настройки если есть
        if name_lower in self.DEFAULT_ZONES:
            defaults = self.DEFAULT_ZONES[name_lower]
            if security_level is None:
                security_level = defaults['level']
            color = defaults['color']
            display_name = defaults['name']
        else:
            color = '#999999'
            display_name = name
            if security_level is None:
                security_level = 50
        
        self.zones[name_lower] = SecurityZone(
            name=display_name,
            security_level=security_level,
            interfaces=interfaces or [],
            description=description,
            color=color
        )
    
    def add_policy(self, from_zone: str, to_zone: str, action: str,
                   services: List[str] = None):
        """Добавляет межзоновую политику."""
        # Определяем риск
        risk_score = self._calculate_risk(from_zone, to_zone, action)
        
        policy = ZonePolicy(
            from_zone=from_zone.lower(),
            to_zone=to_zone.lower(),
            action=action,
            services=services or [],
            risk_score=risk_score
        )
        self.policies.append(policy)
        
        # Проверяем на нарушения
        self._check_violations(policy)
    
    def auto_detect_zones(self, interfaces: Dict, hostname: str = ''):
        """Автоматически определяет зоны по интерфейсам."""
        for iface_name, iface_data in interfaces.items():
            # Определяем зону по имени интерфейса
            zone_name = self._guess_zone_from_interface(iface_name, iface_data)
            
            if zone_name not in self.zones:
                self.add_zone(zone_name)
            
            # Добавляем интерфейс к зоне
            zone = self.zones[zone_name.lower()]
            if hostname:
                zone.interfaces.append(f"{hostname}:{iface_name}")
            else:
                zone.interfaces.append(iface_name)
    
    def _guess_zone_from_interface(self, iface_name: str, iface_data) -> str:
        """Угадывает зону по имени интерфейса."""
        name_lower = iface_name.lower()
        
        if any(x in name_lower for x in ['wan', 'outside', 'ext', 'untrust']):
            return 'Outside'
        elif any(x in name_lower for x in ['dmz', 'srv', 'server']):
            return 'DMZ'
        elif any(x in name_lower for x in ['lan', 'inside', 'int', 'trust', 'mgmt', 'management']):
            return 'Inside'
        elif 'lo' in name_lower or 'loopback' in name_lower:
            return 'Management'
        else:
            # По IP-адресу (если это объект Interface)
            ip = getattr(iface_data, 'ip_address', None)
            if not ip and isinstance(iface_data, dict):
                ip = iface_data.get('ip_address', '')
            if ip:
                # Приватные сети = Inside
                if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.16.'):
                    return 'Inside'
                else:
                    return 'Outside'
            return 'Inside'  # По умолчанию
    
    def get_zone_graph(self) -> Tuple[List[Dict], List[Dict]]:
        """Возвращает nodes и edges для визуализации зон."""
        nodes = []
        edges = []
        
        # Узлы зон
        for zone_name, zone in self.zones.items():
            nodes.append({
                'id': f'zone_{zone_name}',
                'label': zone.name,
                'group': 'zone',
                'security_level': zone.security_level,
                'color': zone.color,
                'size': 30 + len(zone.interfaces) * 3,
                'title': self._format_zone_tooltip(zone)
            })
        
        # Узлы устройств (если есть интерфейсы)
        devices = set()
        for zone in self.zones.values():
            for iface in zone.interfaces:
                if ':' in iface:
                    devices.add(iface.split(':')[0])
        
        for device in sorted(devices):
            nodes.append({
                'id': f'dev_{device}',
                'label': device,
                'group': 'device',
                'color': '#667eea',
                'size': 20
            })
            
            # Связь устройства с зонами
            for zone_name, zone in self.zones.items():
                for iface in zone.interfaces:
                    if iface.startswith(f"{device}:"):
                        edges.append({
                            'from': f'dev_{device}',
                            'to': f'zone_{zone_name}',
                            'label': iface.split(':')[1],
                            'color': {'color': zone.color},
                            'width': 2,
                            'dashes': True
                        })
        
        # Рёбра политик
        for policy in self.policies:
            if policy.from_zone in self.zones and policy.to_zone in self.zones:
                color = '#00AA00' if policy.action == 'permit' else '#FF0000'
                edges.append({
                    'from': f'zone_{policy.from_zone}',
                    'to': f'zone_{policy.to_zone}',
                    'label': policy.action,
                    'color': {'color': color},
                    'width': 1 + policy.risk_score / 3,
                    'arrows': 'to',
                    'title': f'Risk: {policy.risk_score:.1f}'
                })
        
        return nodes, edges
    
    def get_zone_matrix(self) -> Dict:
        """Возвращает матрицу зон (from -> to)."""
        zones = sorted(self.zones.keys())
        
        matrix = {}
        for from_z in zones:
            matrix[from_z] = {}
            for to_z in zones:
                # Ищем политику
                policies = [p for p in self.policies 
                          if p.from_zone == from_z and p.to_zone == to_z]
                
                if policies:
                    # Берём самую строгую
                    deny = any(p.action == 'deny' for p in policies)
                    action = 'deny' if deny else 'permit'
                    risk = max(p.risk_score for p in policies)
                    matrix[from_z][to_z] = {
                        'action': action,
                        'risk': risk,
                        'rules': len(policies)
                    }
                else:
                    matrix[from_z][to_z] = None
        
        return {
            'zones': {z: {'name': self.zones[z].name, 'level': self.zones[z].security_level} 
                     for z in zones},
            'matrix': matrix,
            'violations': [
                {
                    'from': v.from_zone,
                    'to': v.to_zone,
                    'severity': v.severity,
                    'description': v.description
                }
                for v in self.violations
            ]
        }
    
    def _calculate_risk(self, from_zone: str, to_zone: str, action: str) -> float:
        """Вычисляет риск политики."""
        if action == 'deny':
            return 0.0
        
        # Проверяем рискованные направления
        if (from_zone, to_zone) in self.HIGH_RISK_FLOWS:
            return 8.0
        
        # Риск на основе разницы уровней безопасности
        from_level = self.zones.get(from_zone, SecurityZone(''))
        to_level = self.zones.get(to_zone, SecurityZone(''))
        
        level_diff = abs(from_level.security_level - to_level.security_level)
        
        if from_zone == to_zone:
            return 1.0  # Intra-zone
        elif level_diff > 50:
            return 7.0  # Большая разница в уровнях
        elif level_diff > 20:
            return 4.0
        else:
            return 2.0
    
    def _check_violations(self, policy: ZonePolicy):
        """Проверяет политику на нарушения."""
        if (policy.from_zone, policy.to_zone) in self.HIGH_RISK_FLOWS:
            if policy.action == 'permit':
                self.violations.append(ZoneViolation(
                    from_zone=policy.from_zone,
                    to_zone=policy.to_zone,
                    severity='high',
                    description=f'Разрешён доступ из {policy.from_zone} в {policy.to_zone}',
                    recommendation='Ограничить доступ или добавить inspection'
                ))
        
        # Outside -> Inside без ограничений
        if policy.from_zone in ['outside', 'untrust'] and policy.to_zone in ['inside', 'trust', 'management']:
            if policy.action == 'permit' and not policy.services:
                self.violations.append(ZoneViolation(
                    from_zone=policy.from_zone,
                    to_zone=policy.to_zone,
                    severity='critical',
                    description='Открытый доступ из внешней сети во внутреннюю',
                    recommendation='Разрешить только необходимые сервисы'
                ))
    
    def _format_zone_tooltip(self, zone: SecurityZone) -> str:
        """Форматирует tooltip для зоны."""
        lines = [
            f'Зона: {zone.name}',
            f'Уровень безопасности: {zone.security_level}',
            f'Интерфейсов: {len(zone.interfaces)}',
        ]
        if zone.interfaces:
            lines.append(f'Интерфейсы: {zone.interfaces}')
        return '\\n'.join(lines)


# Экспорт
__all__ = ['SecurityZoneBuilder', 'SecurityZone', 'ZonePolicy', 'ZoneViolation']
