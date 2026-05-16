"""
Security Zone Topology Builder — топология зон безопасности.

Строит граф межзонового доступа из:
- Зон, определённых в конфигах (Cisco ASA security-level, Juniper zones)
- Назначений интерфейсов в зоны (из конфигов устройств)
- Firewall-правил (источники/назначения с зонами из Endpoint.zone)

Выдаёт:
- Vis.js nodes/edges с цветовой разметкой зон
- Zone matrix (межзоновая матрица доступа)
- Список нарушений (violations)
- Summary-статистику

Используется:
- Как CLI entrypoint: --zone-view, --zone-matrix
- Как библиотечный компонент из main.py
"""

import re
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict
from itertools import product


# ─── Data models ────────────────────────────────────────────────────────────

@dataclass
class SecurityZone:
    """Зона безопасности (Inside, Outside, DMZ и т.д.)."""
    name: str                          # отображаемое имя
    key: str                           # ключ (lowercase)
    security_level: int = 0            # 0-100, выше = безопаснее
    interfaces: List[str] = field(default_factory=list)
    devices: Set[str] = field(default_factory=set)
    ip_ranges: List[str] = field(default_factory=list)
    description: str = ''
    color: str = '#90EE90'
    rules_in: int = 0                  # входящие правила
    rules_out: int = 0                 # исходящие правила


@dataclass
class ZonePolicy:
    """Политика между зонами (разрешённый или запрещённый трафик)."""
    from_zone: str
    to_zone: str
    action: str                        # permit / deny / inspect
    services: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    rules_count: int = 0
    source_rule_ids: List[str] = field(default_factory=list)


@dataclass
class ZoneViolation:
    """Нарушение политики зон."""
    from_zone: str
    to_zone: str
    severity: str                      # critical / high / medium / low
    description: str
    recommendation: str
    rule_ids: List[str] = field(default_factory=list)


# ─── Known zone definitions ─────────────────────────────────────────────────

KNOWN_ZONES = {
    'outside':     {'level': 0,   'color': '#FF6B6B', 'name': 'Outside / Untrust'},
    'untrust':     {'level': 0,   'color': '#FF6B6B', 'name': 'Untrust'},
    'internet':    {'level': 0,   'color': '#FF6B6B', 'name': 'Internet'},
    'wan':         {'level': 0,   'color': '#FF6B6B', 'name': 'WAN'},
    'dmz':         {'level': 50,  'color': '#FFA07A', 'name': 'DMZ'},
    'srv':         {'level': 50,  'color': '#FFA07A', 'name': 'Server'},
    'guest':       {'level': 25,  'color': '#F7DC6F', 'name': 'Guest'},
    'inside':      {'level': 100, 'color': '#4ECDC4', 'name': 'Inside / Trust'},
    'trust':       {'level': 100, 'color': '#4ECDC4', 'name': 'Trust'},
    'internal':    {'level': 100, 'color': '#4ECDC4', 'name': 'Internal'},
    'lan':         {'level': 100, 'color': '#4ECDC4', 'name': 'LAN'},
    'management':  {'level': 100, 'color': '#45B7D1', 'name': 'Management'},
    'mgmt':        {'level': 100, 'color': '#45B7D1', 'name': 'Management'},
    'vpn':         {'level': 60,  'color': '#BB8FCE', 'name': 'VPN'},
}

# Направления с высоким риском
HIGH_RISK_PAIRS: Set[Tuple[str, str]] = {
    ('outside', 'inside'),
    ('outside', 'management'),
    ('outside', 'dmz'),
    ('untrust', 'trust'),
    ('untrust', 'inside'),
    ('internet', 'internal'),
    ('dmz', 'inside'),
    ('dmz', 'management'),
    ('guest', 'inside'),
    ('guest', 'dmz'),
}


# ─── Builder ────────────────────────────────────────────────────────────────

class SecurityZoneBuilder:
    """
    Строитель топологии зон безопасности.

    Алгоритм:
    1. Извлечение зон из firewall-правил (Endpoint.zone) + конфигов устройств
    2. Классификация зон по имени (предопределённые уровни безопасности)
    3. Построение межзоновых политик на основе правил
    4. Оценка риска для каждой политики
    5. Поиск нарушений (high-risk flows)
    6. Экспорт в Vis.js (nodes/edges), zone matrix, violations, summary
    """

    # Палитра для нестандартных зон
    FALLBACK_COLORS = [
        '#E74C3C', '#3498DB', '#2ECC71', '#F39C12', '#9B59B6',
        '#1ABC9C', '#E67E22', '#2980B9', '#27AE60', '#D35400',
        '#8E44AD', '#16A085',
    ]

    def __init__(self):
        self.zones: Dict[str, SecurityZone] = {}          # key → SecurityZone
        self.policies: List[ZonePolicy] = []
        self.violations: List[ZoneViolation] = []
        self._fallback_color_idx = 0

    # ── Zone management ─────────────────────────────────────────────────

    def get_or_create_zone(self, name: str) -> SecurityZone:
        """Возвращает существующую зону или создаёт новую."""
        key = name.lower().strip()

        if key in self.zones:
            return self.zones[key]

        # Ищем в предопределённых
        known = KNOWN_ZONES.get(key)

        if known:
            sz = SecurityZone(
                name=known['name'],
                key=key,
                security_level=known['level'],
                color=known['color'],
            )
        else:
            color = self.FALLBACK_COLORS[self._fallback_color_idx % len(self.FALLBACK_COLORS)]
            self._fallback_color_idx += 1

            # Эвристика уровня по имени
            level = 50  # default
            name_lower = name.lower()
            if any(w in name_lower for w in ('outside', 'untrust', 'internet', 'ext', 'wan')):
                level = 0
            elif any(w in name_lower for w in ('inside', 'trust', 'internal', 'int', 'lan')):
                level = 100
            elif any(w in name_lower for w in ('dmz', 'srv', 'server')):
                level = 50
            elif any(w in name_lower for w in ('mgmt', 'management')):
                level = 100

            sz = SecurityZone(
                name=name,
                key=key,
                security_level=level,
                color=color,
            )

        self.zones[key] = sz
        return sz

    def add_zone(self, name: str, security_level: int = None,
                 interfaces: List[str] = None, description: str = ''):
        """Добавляет / обновляет зону."""
        key = name.lower().strip()
        sz = self.get_or_create_zone(name)

        if security_level is not None:
            sz.security_level = security_level
        if interfaces:
            sz.interfaces.extend(interfaces)
        if description:
            sz.description = description

    def auto_detect_zones_from_interfaces(self, interfaces: Dict,
                                          hostname: str = ''):
        """
        Определяет зоны по интерфейсам устройства.
        interfaces: {iface_name: Interface | dict}
        """
        for iface_name, iface_data in interfaces.items():
            zone_name = self._guess_zone_from_interface(iface_name, iface_data)
            sz = self.get_or_create_zone(zone_name)

            label = f"{hostname}:{iface_name}" if hostname else iface_name
            if label not in sz.interfaces:
                sz.interfaces.append(label)
            if hostname:
                sz.devices.add(hostname)

    def _guess_zone_from_interface(self, iface_name: str, iface_data) -> str:
        """Угадывает зону по имени интерфейса."""
        name_lower = iface_name.lower()

        # Имя интерфейса
        if any(x in name_lower for x in ('wan', 'outside', 'ext', 'untrust')):
            return 'Outside'
        if any(x in name_lower for x in ('dmz', 'srv', 'server')):
            return 'DMZ'
        if any(x in name_lower for x in ('lan', 'inside', 'int', 'trust')):
            return 'Inside'
        if any(x in name_lower for x in ('mgmt', 'management')):
            return 'Management'
        if 'lo' in name_lower or 'loopback' in name_lower:
            return 'Management'

        # По IP-адресу (если Interface с ip_address)
        ip = getattr(iface_data, 'ip_address', None)
        if not ip and isinstance(iface_data, dict):
            ip = iface_data.get('ip_address', '')

        if ip:
            ip_str = str(ip).split('/')[0]
            if ip_str.startswith(('10.', '192.168.', '172.16.', '172.17.',
                                  '172.18.', '172.19.', '172.20.', '172.21.',
                                  '172.22.', '172.23.', '172.24.', '172.25.',
                                  '172.26.', '172.27.', '172.28.', '172.29.',
                                  '172.30.', '172.31.')):
                return 'Inside'
            return 'Outside'

        return 'Inside'

    # ── Policy extraction from rules ─────────────────────────────────────

    def extract_zones_from_rules(self, rules, vendor: str = ''):
        """
        Извлекает зоны из firewall-правил.
        Каждое правило содержит sources и destinations, у которых
        может быть поле zone или имя, похожее на зону.

        Также парсит Cisco ASA security-level / Juniper zone из конфига.
        """
        for rule in rules:
            # Собираем зоны источников
            source_zones: Set[str] = set()
            dest_zones: Set[str] = set()

            for src in rule.sources:
                zone_name = self._extract_zone_from_endpoint(src)
                if zone_name:
                    source_zones.add(zone_name)

            for dst in rule.destinations:
                zone_name = self._extract_zone_from_endpoint(dst)
                if zone_name:
                    dest_zones.add(zone_name)

            # Если нет явных зон, назначаем по имени эндпоинта
            if not source_zones:
                for src in rule.sources:
                    guessed = self._guess_zone_from_name(src.name)
                    if guessed:
                        source_zones.add(guessed)

            if not dest_zones:
                for dst in rule.destinations:
                    guessed = self._guess_zone_from_name(dst.name)
                    if guessed:
                        dest_zones.add(guessed)

            # Если совсем ничего — пропускаем
            if not source_zones or not dest_zones:
                continue

            # Регистрируем зоны
            for z in source_zones | dest_zones:
                self.get_or_create_zone(z)

            # Создаём политики (cross-product зон)
            service_names = [s.name for s in rule.services] if rule.services else ['any']

            for sz in source_zones:
                for dz in dest_zones:
                    self._add_policy_from_rule(
                        sz, dz,
                        rule.action.lower(),
                        service_names,
                        rule.name if hasattr(rule, 'rule_id') else '',
                    )

    def _extract_zone_from_endpoint(self, endpoint) -> Optional[str]:
        """Извлекает зону из endpoint."""
        # Явное поле zone
        if hasattr(endpoint, 'zone') and endpoint.zone:
            return endpoint.zone

        # Тип endpoint
        if hasattr(endpoint, 'endpoint_type') and endpoint.endpoint_type == 'zone':
            return endpoint.name

        return None

    def _guess_zone_from_name(self, name: str) -> Optional[str]:
        """Угадывает зону по имени эндпоинта."""
        name_lower = name.lower().strip()

        zone_keywords = {
            'outside':       'Outside',
            'untrust':       'Outside',
            'internet':      'Outside',
            'external':      'Outside',
            'wan':           'Outside',
            'dmz':           'DMZ',
            'inside':        'Inside',
            'trust':         'Inside',
            'internal':      'Inside',
            'lan':           'Inside',
            'management':    'Management',
            'mgmt':          'Management',
            'guest':         'Guest',
            'vpn':           'VPN',
            'partner':       'VPN',
        }

        for keyword, zone in zone_keywords.items():
            if keyword in name_lower:
                return zone

        return None

    def _add_policy_from_rule(self, from_zone: str, to_zone: str,
                               action: str, services: List[str],
                               rule_id: str):
        """Добавляет политику на основе правила."""
        from_key = from_zone.lower().strip()
        to_key = to_zone.lower().strip()

        # Обновляем счётчики зон
        if from_key in self.zones:
            self.zones[from_key].rules_out += 1
        if to_key in self.zones:
            self.zones[to_key].rules_in += 1

        # Ищем существующую политику
        existing = None
        for p in self.policies:
            if p.from_zone == from_key and p.to_zone == to_key:
                existing = p
                break

        if existing:
            # Обновляем: самый строгий action (deny переопределяет permit)
            if action == 'deny':
                existing.action = 'deny'
            existing.services.extend(s for s in services if s not in existing.services)
            existing.rules_count += 1
            existing.risk_score = max(existing.risk_score,
                                      self._calculate_risk(from_key, to_key, existing.action))
            if rule_id:
                existing.source_rule_ids.append(rule_id)
        else:
            risk = self._calculate_risk(from_key, to_key, action)
            policy = ZonePolicy(
                from_zone=from_key,
                to_zone=to_key,
                action='deny' if action == 'deny' else 'permit',
                services=list(services),
                risk_score=risk,
                rules_count=1,
                source_rule_ids=[rule_id] if rule_id else [],
            )
            self.policies.append(policy)

            # Проверяем на нарушения
            self._check_violations(policy)

    def _calculate_risk(self, from_zone: str, to_zone: str, action: str) -> float:
        """Вычисляет риск межзоновой политики."""
        if action == 'deny':
            return 0.0

        from_key = from_zone.lower().strip()
        to_key = to_zone.lower().strip()

        # High-risk пары
        if (from_key, to_key) in HIGH_RISK_PAIRS:
            return 8.0

        # Разница уровней безопасности
        from_level = self.zones[from_key].security_level if from_key in self.zones else 50
        to_level = self.zones[to_key].security_level if to_key in self.zones else 50

        if from_key == to_key:
            return 1.0  # intra-zone
        elif from_level > to_level and (from_level - to_level) > 50:
            return 7.0  # из защищённой в менее защищённую с большой разницей
        elif from_level < to_level and (to_level - from_level) > 50:
            return 7.0  # из недоверенной в доверенную
        elif abs(from_level - to_level) > 20:
            return 4.0
        else:
            return 2.0

    def _check_violations(self, policy: ZonePolicy):
        """Проверяет политику на нарушения best-practices."""
        if policy.action != 'permit':
            return

        from_key = policy.from_zone
        to_key = policy.to_zone

        pair = (from_key, to_key)

        # High severity: из недоверенной во внутреннюю
        if from_key in ('outside', 'untrust', 'internet') and \
           to_key in ('inside', 'trust', 'internal', 'management', 'mgmt'):
            sev = 'critical' if not policy.services or 'any' in policy.services else 'high'
            self.violations.append(ZoneViolation(
                from_zone=from_key,
                to_zone=to_key,
                severity=sev,
                description=f'Доступ из {from_key} в {to_key}'
                             f'{" без ограничения сервисов" if sev == "critical" else ""}',
                recommendation='Разрешить только минимально необходимые сервисы '
                               '(принцип наименьших привилегий)',
                rule_ids=policy.source_rule_ids,
            ))

        # High: DMZ → Internal
        if from_key in ('dmz',) and to_key in ('inside', 'trust', 'internal', 'management'):
            self.violations.append(ZoneViolation(
                from_zone=from_key,
                to_zone=to_key,
                severity='high',
                description=f'Доступ из {from_key} во внутреннюю сеть {to_key}',
                recommendation='Изолировать DMZ от внутренней сети, '
                               'использовать reverse proxy или промежуточный сервер',
                rule_ids=policy.source_rule_ids,
            ))

        # Medium: Guest → Internal
        if from_key in ('guest',) and to_key in ('inside', 'trust', 'internal', 'dmz'):
            self.violations.append(ZoneViolation(
                from_zone=from_key,
                to_zone=to_key,
                severity='medium',
                description=f'Доступ из гостевой сети {from_key} в {to_key}',
                recommendation='Гостевая сеть должна быть полностью изолирована',
                rule_ids=policy.source_rule_ids,
            ))

    # ── Vis.js export ────────────────────────────────────────────────────

    def to_visjs(self) -> Tuple[List[Dict], List[Dict]]:
        """
        Экспорт в формат Vis.js: (nodes, edges).

        Граф:
        - Узлы-зоны (крупные цветные области, размер пропорционален правилам)
        - Узлы-устройства подключены к зонам (опционально, пунктиром)
        - Рёбра-политики между зонами (направленные, цвет по действию, толщина = кол-во правил)

        Совместим с GraphVisualizer.
        """
        nodes: List[Dict] = []
        edges: List[Dict] = []

        # Сортируем зоны: по уровню безопасности (снаружи внутрь)
        sorted_zones = sorted(
            self.zones.items(),
            key=lambda kv: (kv[1].security_level, kv[0])
        )

        # ── Zone nodes ──────────────────────────────────────────────────
        for key, zone in sorted_zones:
            total_rules = zone.rules_in + zone.rules_out
            size = 35 + total_rules * 2

            tags = []
            if zone.security_level == 0:
                tags.append('⚠️ Untrusted')
            elif zone.security_level >= 100:
                tags.append('🔒 Trusted')
            if zone.security_level == 50:
                tags.append('🌐 DMZ')

            # Определяем иконку
            if zone.security_level >= 100:
                icon_code = '🔒'
            elif zone.security_level == 50:
                icon_code = '🌐'
            else:
                icon_code = '⚠️'

            nodes.append({
                'id': f'zone_{key}',
                'label': f'{icon_code} {zone.name}',
                'group': 'zone',
                'security_level': zone.security_level,
                'color': zone.color,
                'size': size,
                'borderWidth': 3,
                'borderWidthSelected': 5,
                'title': (
                    f'Зона: {zone.name}\n'
                    f'Уровень безопасности: {zone.security_level}/100\n'
                    f'Интерфейсов: {len(zone.interfaces)}\n'
                    f'Устройств: {len(zone.devices)}\n'
                    f'Входящих правил: {zone.rules_in}\n'
                    f'Исходящих правил: {zone.rules_out}\n'
                    f'{"; ".join(tags)}'
                ),
            })

        # ── Device nodes ────────────────────────────────────────────────
        all_devices: Set[str] = set()
        for zone in self.zones.values():
            all_devices.update(zone.devices)

        for device in sorted(all_devices):
            nodes.append({
                'id': f'dev_{device}',
                'label': device,
                'group': 'device',
                'color': '#8899aa',
                'size': 18,
                'shape': 'dot',
            })

            # Связь устройства с зонами (пунктир)
            for key, zone in self.zones.items():
                for iface in zone.interfaces:
                    if iface.startswith(f"{device}:") or iface == device:
                        edges.append({
                            'from': f'dev_{device}',
                            'to': f'zone_{key}',
                            'label': iface.replace(f'{device}:', '') if f'{device}:' in iface else '',
                            'color': {'color': zone.color, 'opacity': 0.4},
                            'width': 1,
                            'dashes': True,
                            'arrows': '',
                            'title': f'Интерфейс: {iface}',
                        })

        # ── Policy edges ────────────────────────────────────────────────
        for policy in self.policies:
            from_id = f'zone_{policy.from_zone}'
            to_id = f'zone_{policy.to_zone}'

            if policy.from_zone not in self.zones or policy.to_zone not in self.zones:
                continue

            if policy.action == 'permit':
                edge_color = '#00AA00' if policy.risk_score < 5 else '#FFA500'
                if policy.risk_score >= 7:
                    edge_color = '#FF0000'
            elif policy.action == 'inspect':
                edge_color = '#FFA500'
            else:
                edge_color = '#CC0000'

            width = 1 + policy.rules_count
            if width > 8:
                width = 8

            edges.append({
                'from': from_id,
                'to': to_id,
                'label': f'{policy.action} ({policy.rules_count})',
                'color': {'color': edge_color},
                'width': width,
                'arrows': 'to',
                'dashes': policy.action == 'deny',
                'title': (
                    f'{policy.from_zone} → {policy.to_zone}\n'
                    f'Действие: {policy.action}\n'
                    f'Сервисы: {", ".join(policy.services[:5])}'
                    f'{"…" if len(policy.services) > 5 else ""}\n'
                    f'Правил: {policy.rules_count}\n'
                    f'Риск: {policy.risk_score:.1f}/10'
                ),
            })

        return nodes, edges

    # ── Zone matrix ─────────────────────────────────────────────────────

    def get_zone_matrix(self) -> Dict:
        """
        Матрица межзонового доступа: {zone_from: {zone_to: info}}.

        Используется для экспорта JSON и визуализации матрицы.
        """
        zone_keys = sorted(self.zones.keys(),
                           key=lambda k: self.zones[k].security_level)

        matrix = {}
        for from_k in zone_keys:
            matrix[from_k] = {}
            for to_k in zone_keys:
                # Ищем политики from_k → to_k
                matched = [p for p in self.policies
                          if p.from_zone == from_k and p.to_zone == to_k]

                if matched:
                    has_deny = any(p.action == 'deny' for p in matched)
                    action = 'deny' if has_deny else 'permit'
                    max_risk = max(p.risk_score for p in matched)
                    total_rules = sum(p.rules_count for p in matched)
                    services = list({s for p in matched for s in p.services})

                    matrix[from_k][to_k] = {
                        'action': action,
                        'risk': max_risk,
                        'rules_count': total_rules,
                        'services': services[:10],  # ограничиваем
                    }
                else:
                    # Если нет политики, по умолчанию deny (implicit deny)
                    # Но intra-zone обычно разрешён
                    implicit_action = 'permit' if from_k == to_k else 'deny'
                    matrix[from_k][to_k] = {
                        'action': implicit_action,
                        'risk': 0,
                        'rules_count': 0,
                        'services': [],
                        'implicit': True,
                    }

        return {
            'zones': {
                k: {
                    'name': self.zones[k].name,
                    'level': self.zones[k].security_level,
                    'color': self.zones[k].color,
                    'interfaces': len(self.zones[k].interfaces),
                    'rules_in': self.zones[k].rules_in,
                    'rules_out': self.zones[k].rules_out,
                }
                for k in zone_keys
            },
            'zone_order': zone_keys,
            'matrix': matrix,
            'violations_count': len(self.violations),
            'violations_summary': {
                'critical': sum(1 for v in self.violations if v.severity == 'critical'),
                'high': sum(1 for v in self.violations if v.severity == 'high'),
                'medium': sum(1 for v in self.violations if v.severity == 'medium'),
                'low': sum(1 for v in self.violations if v.severity == 'low'),
            },
        }

    # ── Violations ──────────────────────────────────────────────────────

    def get_violations(self) -> List[Dict]:
        """Список нарушений в JSON-формате."""
        return [
            {
                'from_zone': v.from_zone,
                'to_zone': v.to_zone,
                'severity': v.severity,
                'description': v.description,
                'recommendation': v.recommendation,
                'rule_count': len(v.rule_ids),
            }
            for v in sorted(
                self.violations,
                key=lambda v: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(v.severity, 4)
            )
        ]

    # ── Summary ─────────────────────────────────────────────────────────

    def summary(self) -> Dict:
        """Сводная статистика топологии зон."""
        zone_list = []
        for key, zone in sorted(self.zones.items(),
                                key=lambda kv: kv[1].security_level):
            zone_list.append({
                'key': key,
                'name': zone.name,
                'level': zone.security_level,
                'interfaces': len(zone.interfaces),
                'devices': len(zone.devices),
                'rules_in': zone.rules_in,
                'rules_out': zone.rules_out,
            })

        return {
            'zones_count': len(self.zones),
            'policies_count': len(self.policies),
            'violations_count': len(self.violations),
            'high_risk_policies': sum(1 for p in self.policies if p.risk_score >= 7),
            'zones': zone_list,
            'violations_by_severity': {
                'critical': sum(1 for v in self.violations if v.severity == 'critical'),
                'high': sum(1 for v in self.violations if v.severity == 'high'),
                'medium': sum(1 for v in self.violations if v.severity == 'medium'),
                'low': sum(1 for v in self.violations if v.severity == 'low'),
            },
        }

    # ── Cisco ASA / Juniper zone parser ─────────────────────────────────

    def parse_cisco_asa_zones(self, content: str, hostname: str = ''):
        """
        Парсит Cisco ASA security-level из конфига.
        
        Пример:
            interface GigabitEthernet0/1
             nameif outside
             security-level 0
             ip address 203.0.113.1 255.255.255.0
        """
        for m in re.finditer(
            r'interface\s+(\S+)\s*\n((?:(?!^interface\s).*\n)*)',
            content,
            re.MULTILINE
        ):
            iface = m.group(1)
            block = m.group(2)

            nameif_m = re.search(r'nameif\s+(\S+)', block)
            level_m = re.search(r'security-level\s+(\d+)', block)

            if nameif_m:
                zone_name = nameif_m.group(1)
                level = int(level_m.group(1)) if level_m else 50
                self.add_zone(
                    zone_name, security_level=level,
                    interfaces=[f"{hostname}:{iface}" if hostname else iface],
                )

    def parse_juniper_zones(self, content: str, hostname: str = ''):
        """
        Парсит Juniper SRX security zones.

        Пример:
            security-zone untrust {
                interfaces {
                    ge-0/0/0.0;
                }
            }
        """
        for m in re.finditer(
            r'security-zone\s+(\S+)\s*\{((?:[^{}]|\{[^{}]*\})*)\}',
            content,
            re.DOTALL
        ):
            zone_name = m.group(1)
            block = m.group(2)

            # Interfaces
            interfaces = re.findall(r'(\S+?);', block)

            self.add_zone(
                zone_name,
                interfaces=[f"{hostname}:{i}" if hostname else i
                           for i in interfaces],
            )

    def parse_device_config(self, content: str, vendor: str,
                             hostname: str = ''):
        """
        Парсит конфигурацию устройства на предмет зон.
        Поддерживает: Cisco ASA, Juniper SRX.
        """
        vendor_lower = vendor.lower()

        if vendor_lower in ('cisco_asa', 'asa', 'cisco_ios'):
            self.parse_cisco_asa_zones(content, hostname)
        elif vendor_lower in ('juniper', 'junos', 'juniper_srx'):
            self.parse_juniper_zones(content, hostname)
        # Aruba CX / HP — зоны определяются через интерфейсы (auto_detect)


# ─── CLI integration ───────────────────────────────────────────────────────

def build_zone_topology(
    rules=None,
    config_dir=None,
    vendor: Optional[str] = None,
    topology_data=None,
) -> Tuple[List[Dict], List[Dict], SecurityZoneBuilder]:
    """
    Точка входа: строит Security Zone Topology.

    Принимает:
    - rules: список FirewallRule (из парсера)
    - config_dir: путь к директории с конфигами (для парсинга device zones)
    - vendor: вендор устройств
    - topology_data: предварительно спарсенные данные топологии

    Возвращает (nodes, edges, builder) — nodes/edges для Vis.js + builder для
    дополнительных запросов (matrix, violations, summary).

    Использование:
        from src.core.zone_topology import build_zone_topology
        nodes, edges, builder = build_zone_topology(rules, 'configs/')
    """
    builder = SecurityZoneBuilder()

    # 1. Извлекаем зоны из firewall-правил
    if rules:
        builder.extract_zones_from_rules(rules, vendor=vendor or '')

    # 2. Парсим device конфиги (Cisco ASA / Juniper zones)
    if config_dir:
        config_path = Path(config_dir)
        for f in sorted(config_path.glob('*.txt')):
            try:
                content = f.read_text(encoding='utf-8', errors='ignore')
                hostname = f.stem
                # Пробуем разные форматы
                builder.parse_device_config(content, 'cisco_asa', hostname)
                builder.parse_device_config(content, 'juniper', hostname)
            except Exception:
                pass

    # 3. Считаем статистику
    stats = builder.summary()

    print(f"[Zone Topology] {stats['zones_count']} зон безопасности, "
          f"{stats['policies_count']} межзоновых политик")
    print(f"  Нарушений: {stats['violations_count']} "
          f"(critical: {stats['violations_by_severity']['critical']}, "
          f"high: {stats['violations_by_severity']['high']})")

    if stats['high_risk_policies']:
        print(f"  Высокорисковых политик: {stats['high_risk_policies']}")

    for z in stats['zones']:
        flags = []
        if z['level'] == 0:
            flags.append('⚠️ untrusted')
        elif z['level'] >= 100:
            flags.append('🔒 trusted')
        if z['level'] == 50:
            flags.append('🌐 DMZ')

        flag_str = f' ({"; ".join(flags)})' if flags else ''
        print(f"  {z['name']}: level={z['level']}, "
              f"interfaces={z['interfaces']}, "
              f"in={z['rules_in']}, out={z['rules_out']}{flag_str}")

    # 4. Экспортируем Vis.js
    nodes, edges = builder.to_visjs()
    return nodes, edges, builder


# ── Backward-compatible aliases ────────────────────────────────────────

    # Alias for old API
    def auto_detect_zones(self, interfaces, hostname: str = ''):
        """Alias for auto_detect_zones_from_interfaces."""
        return self.auto_detect_zones_from_interfaces(interfaces, hostname)

    def get_zone_graph(self) -> Tuple[List[Dict], List[Dict]]:
        """Alias for to_visjs()."""
        return self.to_visjs()


# Экспорт
__all__ = [
    'SecurityZone',
    'ZonePolicy',
    'ZoneViolation',
    'SecurityZoneBuilder',
    'build_zone_topology',
    'KNOWN_ZONES',
    'HIGH_RISK_PAIRS',
]
