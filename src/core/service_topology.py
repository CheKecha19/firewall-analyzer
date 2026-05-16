"""
Service/App Topology Builder — сервисная топология приложений.

Строит граф зависимостей сервисов/приложений из firewal-правил:
- Узлы-сервисы сгруппированы по слоям: presentation / application / data
- Рёбра — сетевые взаимодействия с портами и протоколами
- Автоопределение слоя по порту/протоколу: Web (80/443) → presentation,
  API (8080/8443) → application, DB (3306/5432/1433) → data

Выдаёт:
- Vis.js nodes/edges с цветовой разметкой по слоям
- Service dependency matrix
- Сводную статистику
- CLI entrypoint: --svc-view

Используется:
- Как автономный модуль из main.py
- Как библиотечный компонент для Web UI
"""

from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import re


# ─── Layer definitions ──────────────────────────────────────────────────────

@dataclass
class ServiceLayer:
    """Слой сервисной архитектуры."""
    name: str                          # Presentation / Application / Data
    key: str                           # presentation / application / data
    color: str                         # цвет для Vis.js
    order: int                         # для vertical layout
    icon: str                          # emoji-иконка для label
    description: str


LAYERS = {
    'presentation': ServiceLayer(
        name='Presentation',
        key='presentation',
        color='#3498DB',               # синий
        order=0,
        icon='🌐',
        description='Web-серверы, CDN, Load Balancers, Reverse Proxy'
    ),
    'application': ServiceLayer(
        name='Application',
        key='application',
        color='#2ECC71',               # зелёный
        order=1,
        icon='🔌',
        description='API-серверы, бизнес-логика, Message Queues'
    ),
    'data': ServiceLayer(
        name='Data',
        key='data',
        color='#E67E22',               # оранжевый
        order=2,
        icon='🗄️',
        description='Базы данных, файловые хранилища, кэши'
    ),
    'external': ServiceLayer(
        name='External',
        key='external',
        color='#E74C3C',               # красный
        order=3,
        icon='🌍',
        description='Внешние API, облачные сервисы, third-party'
    ),
    'infrastructure': ServiceLayer(
        name='Infrastructure',
        key='infrastructure',
        color='#9B59B6',               # фиолетовый
        order=-1,                       # ниже/выше всех
        icon='⚙️',
        description='Мониторинг, логирование, DNS, NTP, Auth/LDAP'
    ),
}

# Маппинг портов на слои (самые частые)
PORT_LAYER_MAP: Dict[int, str] = {
    # Presentation
    80:   'presentation',
    443:  'presentation',
    8000: 'presentation',
    8443: 'presentation',
    # Application
    8080: 'application',
    8443: 'application',
    8001: 'application',
    9000: 'application',
    # Data
    3306: 'data',
    5432: 'data',
    1433: 'data',
    1521: 'data',
    27017: 'data',
    6379: 'data',
    11211: 'data',
    9200: 'data',
    9092: 'application',   # Kafka — application layer
    5672: 'application',   # RabbitMQ
    9042: 'data',          # Cassandra
    # Infrastructure
    22:   'infrastructure',
    25:   'infrastructure',
    53:   'infrastructure',
    123:  'infrastructure',
    161:  'infrastructure',
    162:  'infrastructure',
    389:  'infrastructure',
    636:  'infrastructure',
    88:   'infrastructure',   # Kerberos
    514:  'infrastructure',   # Syslog
    2049: 'data',              # NFS — data layer
}

# Маппинг ключевых слов имён на слои
NAME_LAYER_HINTS: Dict[str, str] = {
    'web':     'presentation',
    'www':     'presentation',
    'nginx':   'presentation',
    'apache':  'presentation',
    'cdn':     'presentation',
    'lb':      'presentation',
    'balancer':'presentation',
    'proxy':   'presentation',
    'frontend':'presentation',

    'api':     'application',
    'app':     'application',
    'svc':     'application',
    'service': 'application',
    'worker':  'application',
    'backend': 'application',
    'mq':      'application',
    'queue':   'application',
    'bus':     'application',
    'kafka':   'application',
    'rabbitmq':'application',
    'pubsub':  'application',

    'db':      'data',
    'mysql':   'data',
    'postgres':'data',
    'mongo':   'data',
    'redis':   'data',
    'elastic': 'data',
    'cassandra':'data',
    'oracle':  'data',
    'sql':     'data',
    'storage': 'data',
    'fs':      'data',
    'nfs':     'data',

    'dns':     'infrastructure',
    'ntp':     'infrastructure',
    'ldap':    'infrastructure',
    'ad':      'infrastructure',
    'auth':    'infrastructure',
    'sso':     'infrastructure',
    'monitor': 'infrastructure',
    'log':     'infrastructure',
    'syslog':  'infrastructure',
    'snmp':    'infrastructure',
    'smtp':    'infrastructure',

    'external':'external',
    'partner': 'external',
    'cloud':   'external',
}


# ─── Data models ────────────────────────────────────────────────────────────

@dataclass
class ServiceNode:
    """Узел-сервис в топологии."""
    id: str                           # уникальный идентификатор
    name: str                         # отображаемое имя
    layer: str                        # presentation / application / data / external / infrastructure
    ips: List[str] = field(default_factory=list)        # IP-адреса сервиса
    ports: List[int] = field(default_factory=list)       # слушающие порты
    protocols: List[str] = field(default_factory=list)   # протоколы (TCP/UDP)
    dependencies: List[str] = field(default_factory=list)  # от каких сервисов зависит
    consumers: List[str] = field(default_factory=list)     # какие сервисы используют этот
    risk_score: float = 0.0
    is_critical: bool = False
    description: str = ''
    device_hostname: str = ''


@dataclass
class ServiceEdge:
    """Ребро — сетевое взаимодействие между сервисами."""
    from_service: str
    to_service: str
    protocol: str                    # TCP / UDP / ICMP
    ports: List[int] = field(default_factory=list)
    action: str = 'permit'           # permit / deny
    rules_count: int = 0
    bandwidth_hint: str = ''         # "1G", "10G"
    risk_score: float = 0.0


# ─── Builder ────────────────────────────────────────────────────────────────

class ServiceTopologyBuilder:
    """
    Строитель сервисной топологии.

    Алгоритм:
    1. Извлечение сервисов из firewall-правил (по портам, IP, названиям)
    2. Классификация сервисов по слоям (presentation/app/data/external/infra)
    3. Построение зависимостей между сервисами
    4. Оценка риска
    5. Экспорт в Vis.js, матрицу зависимостей, summary
    """

    def __init__(self):
        self.services: Dict[str, ServiceNode] = {}   # id → ServiceNode
        self.edges: List[ServiceEdge] = []
        self._next_id = 0

    def _make_id(self, prefix: str = 'svc') -> str:
        self._next_id += 1
        return f'{prefix}_{self._next_id}'

    # ── Layer detection ─────────────────────────────────────────────────

    def _guess_layer(self, name: str, ports: List[int],
                     protocols: List[str]) -> str:
        """
        Определяет слой сервиса.

        Приоритет:
        1. По портам (самое точное)
        2. По имени сервиса (ключевые слова)
        3. По протоколам
        4. Default → application
        """
        # 1. По портам
        layer_votes: Dict[str, int] = defaultdict(int)
        for port in ports:
            layer = PORT_LAYER_MAP.get(port)
            if layer:
                layer_votes[layer] += 2   # порты имеют больший вес

        # 2. По имени
        name_lower = name.lower()
        for keyword, layer in NAME_LAYER_HINTS.items():
            if keyword in name_lower:
                layer_votes[layer] += 1

        # 3. По протоколам (если только ICMP → infrastructure)
        if 'icmp' in [p.lower() for p in protocols]:
            layer_votes['infrastructure'] += 1

        if layer_votes:
            return max(layer_votes, key=layer_votes.get)

        return 'application'  # default

    def _guess_name_from_port(self, port: int) -> str:
        """Определяет типовое имя сервиса по порту."""
        WELL_KNOWN = {
            80:   'HTTP',
            443:  'HTTPS',
            22:   'SSH',
            25:   'SMTP',
            53:   'DNS',
            123:  'NTP',
            161:  'SNMP',
            389:  'LDAP',
            636:  'LDAPS',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB',
            9200: 'Elasticsearch',
            9092: 'Kafka',
            5672: 'RabbitMQ',
            11211: 'Memcached',
            8000: 'Web-App',
            8080: 'API',
            8443: 'API-Secure',
            9000: 'App-Server',
        }
        return WELL_KNOWN.get(port, f'service:{port}')

    # ── Service extraction from rules ───────────────────────────────────

    def extract_services_from_rules(self, rules,
                                     object_resolver=None) -> int:
        """
        Извлекает сервисы из firewall-правил.

        Каждое правило имеет:
        - sources: список endpoints
        - destinations: список endpoints
        - services: список протоколов/портов

        Returns: количество извлечённых сервисов.
        """
        service_index: Dict[str, str] = {}  # (ip:port) → service_id
        initial_count = len(self.services)

        for rule in rules:
            # Собираем порты и протоколы из правила
            rule_ports: List[int] = []
            rule_protocols: List[str] = []

            if hasattr(rule, 'service') and rule.service:
                rule_ports = list(rule.service.ports) if hasattr(rule.service, 'ports') else []
                rule_protocols = [rule.service.protocol] if hasattr(rule.service, 'protocol') else []
            elif hasattr(rule, 'services') and rule.services:
                for svc in rule.services:
                    if hasattr(svc, 'ports'):
                        rule_ports.extend(svc.ports or [])
                    if hasattr(svc, 'protocol'):
                        rule_protocols.append(svc.protocol)
                    elif hasattr(svc, 'name'):
                        rule_protocols.append(svc.name)
                rule_ports = list({p for p in rule_ports if p})

            # Извлекаем destination-сервисы (то, куда идёт трафик)
            for dst in rule.destinations:
                dst_ip = self._get_endpoint_ip(dst)
                dst_name = self._get_endpoint_name(dst)
                dst_zone = getattr(dst, 'zone', '') if hasattr(dst, 'zone') else ''

                # Создаём сервис для destination (слушающий порт)
                for port in (rule_ports or [0]):
                    svc_key = f'{dst_ip}:{port}' if dst_ip else f'{dst_name}:{port}'
                    if svc_key in service_index:
                        continue

                    svc_name = dst_name or self._guess_name_from_port(port) if port else dst_name
                    layer = self._guess_layer(svc_name, rule_ports, rule_protocols)

                    svc_id = self._make_id('svc')
                    self.services[svc_id] = ServiceNode(
                        id=svc_id,
                        name=svc_name,
                        layer=layer,
                        ips=[dst_ip] if dst_ip else [],
                        ports=[port] if port else [],
                        protocols=list(set(rule_protocols)),
                        description=f'{dst_name} ({dst_ip})' if dst_ip else svc_name,
                    )
                    service_index[svc_key] = svc_id

                    # Именительный счётчик на zone (если есть)
                    if dst_zone:
                        self.services[svc_id].description += f' [zone: {dst_zone}]'

            # Обрабатываем source-endpoints как потребителей
            for src in rule.sources:
                src_ip = self._get_endpoint_ip(src)
                src_name = self._get_endpoint_name(src)

                # Ищем/создаём consumer-сервис
                src_svc_id = None
                for port in (rule_ports or [0]):
                    src_key = f'{src_ip}:{port}' if src_ip else f'{src_name}:{port}'
                    if src_key in service_index:
                        src_svc_id = service_index[src_key]
                        break

                if not src_svc_id:
                    src_svc_name = src_name or 'Unknown Client'
                    src_layer = self._guess_layer(src_svc_name, [], [])
                    src_svc_id = self._make_id('cli')
                    self.services[src_svc_id] = ServiceNode(
                        id=src_svc_id,
                        name=src_svc_name,
                        layer=src_layer,
                        ips=[src_ip] if src_ip else [],
                    )
                    if src_ip or src_name:
                        service_index[f'{src_ip or src_name}:0'] = src_svc_id

                # Создаём рёбра от источника к destination-сервисам
                for dst in rule.destinations:
                    dst_ip = self._get_endpoint_ip(dst)
                    dst_name = self._get_endpoint_name(dst)
                    for port in (rule_ports or [0]):
                        dst_key = f'{dst_ip}:{port}' if dst_ip else f'{dst_name}:{port}'
                        dst_svc_id = service_index.get(dst_key)
                        if not dst_svc_id:
                            continue

                        # Добавляем связь
                        edge = ServiceEdge(
                            from_service=src_svc_id,
                            to_service=dst_svc_id,
                            protocol=rule_protocols[0] if rule_protocols else 'tcp',
                            ports=[port] if port else [],
                            action=rule.action.lower() if hasattr(rule, 'action') and rule.action else 'permit',
                            rules_count=1,
                            risk_score=self._calculate_service_risk(
                                src_svc_id, dst_svc_id, rule_ports
                            ),
                        )
                        self.edges.append(edge)

                        # Обновляем зависимости
                        if dst_svc_id not in self.services[src_svc_id].dependencies:
                            self.services[src_svc_id].dependencies.append(dst_svc_id)
                        if src_svc_id not in self.services[dst_svc_id].consumers:
                            self.services[dst_svc_id].consumers.append(src_svc_id)

        return len(self.services) - initial_count

    def _get_endpoint_ip(self, endpoint) -> str:
        """Извлекает IP-адрес из endpoint."""
        if hasattr(endpoint, 'ip') and endpoint.ip:
            return str(endpoint.ip)
        if hasattr(endpoint, 'name') and endpoint.name:
            # Может быть IP в имени
            m = re.match(r'(\d+\.\d+\.\d+\.\d+)', str(endpoint.name))
            if m:
                return m.group(1)
        return ''

    def _get_endpoint_name(self, endpoint) -> str:
        """Извлекает читаемое имя из endpoint."""
        if hasattr(endpoint, 'name') and endpoint.name:
            name = str(endpoint.name)
            # Убираем подсеть (/24 и т.п.)
            if '/' in name:
                name = name.split('/')[0]
            # Не IP-адрес
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', name):
                return ''
            if name.lower() in ('any', 'all', '*'):
                return ''
            return name
        if hasattr(endpoint, 'zone') and endpoint.zone:
            return str(endpoint.zone)
        return ''

    def _calculate_service_risk(self, from_id: str, to_id: str,
                                 ports: List[int]) -> float:
        """Оценивает риск взаимодействия сервисов."""
        risk = 1.0
        to_layer = self.services[to_id].layer if to_id in self.services else 'application'

        # Доступ из external к data — максимальный риск
        from_layer = self.services[from_id].layer if from_id in self.services else 'application'
        if from_layer == 'external' and to_layer in ('data', 'infrastructure'):
            risk = 9.0
        elif from_layer == 'external' and to_layer == 'application':
            risk = 6.0
        elif from_layer == 'application' and to_layer == 'data':
            risk = 4.0

        # Нестандартные порты
        if ports:
            for p in ports:
                if p > 1024 and PORT_LAYER_MAP.get(p) != to_layer:
                    risk += 2.0
                    break

        # DB-сервисы всегда более критичны
        if to_layer == 'data':
            risk = max(risk, 5.0)

        return min(risk, 10.0)

    # ── Manual service registration ─────────────────────────────────────

    def register_service(self, name: str, layer: str = None,
                          ips: List[str] = None, ports: List[int] = None,
                          description: str = '') -> str:
        """
        Регистрирует сервис вручную (для ручного маппинга).

        Returns: service_id.
        """
        svc_id = self._make_id('man')
        if layer is None:
            layer = self._guess_layer(name, ports or [], [])

        self.services[svc_id] = ServiceNode(
            id=svc_id,
            name=name,
            layer=layer,
            ips=ips or [],
            ports=ports or [],
            description=description or name,
        )

        return svc_id

    def add_dependency(self, from_svc_id: str, to_svc_id: str,
                        protocol: str = 'tcp', port: int = 0):
        """Добавляет ручную зависимость между сервисами."""
        if from_svc_id not in self.services or to_svc_id not in self.services:
            return

        edge = ServiceEdge(
            from_service=from_svc_id,
            to_service=to_svc_id,
            protocol=protocol,
            ports=[port] if port else [],
            action='permit',
            rules_count=0,
            risk_score=self._calculate_service_risk(
                from_svc_id, to_svc_id, [port] if port else []
            ),
        )
        self.edges.append(edge)

        if to_svc_id not in self.services[from_svc_id].dependencies:
            self.services[from_svc_id].dependencies.append(to_svc_id)
        if from_svc_id not in self.services[to_svc_id].consumers:
            self.services[to_svc_id].consumers.append(from_svc_id)

    # ── Post-processing: aggregate edges ────────────────────────────────

    def _aggregate_edges(self):
        """Агрегирует повторяющиеся рёбра (from, to одинаковые)."""
        edge_map: Dict[Tuple[str, str], ServiceEdge] = {}

        for e in self.edges:
            key = (e.from_service, e.to_service)
            if key in edge_map:
                existing = edge_map[key]
                existing.rules_count += e.rules_count
                existing.risk_score = max(existing.risk_score, e.risk_score)
                # Мержим порты
                for p in e.ports:
                    if p and p not in existing.ports:
                        existing.ports.append(p)
                # Merging протоколов
                if e.protocol not in existing.protocol:
                    existing.protocol = f'{existing.protocol}+{e.protocol}'
            else:
                edge_map[key] = ServiceEdge(
                    from_service=e.from_service,
                    to_service=e.to_service,
                    protocol=e.protocol,
                    ports=list(e.ports),
                    action=e.action,
                    rules_count=e.rules_count,
                    bandwidth_hint=e.bandwidth_hint,
                    risk_score=e.risk_score,
                )

        self.edges = list(edge_map.values())

    # ── Criticality detection ───────────────────────────────────────────

    def _mark_critical_services(self):
        """Помечает критические сервисы."""
        for svc_id, svc in self.services.items():
            # Data layer + много потребителей = критичный
            if svc.layer == 'data' and len(svc.consumers) >= 2:
                svc.is_critical = True
            # Infrastructure всегда критична
            if svc.layer == 'infrastructure':
                svc.is_critical = True
            # Высокий риск
            if svc.risk_score >= 7:
                svc.is_critical = True

    # ── Vis.js export ────────────────────────────────────────────────────

    def to_visjs(self) -> Tuple[List[Dict], List[Dict]]:
        """
        Экспорт в формат Vis.js: (nodes, edges).

        Граф:
        - Узлы-сервисы (цвет по слою, иконка-emoji, размер = кол-во потребителей)
        - Вертикальная раскладка: Presentation сверху → Data снизу
        - Рёбра-зависимости (направленные, цвет = риск, подпись = порты)
        """
        self._aggregate_edges()
        self._mark_critical_services()

        nodes: List[Dict] = []
        edges: List[Dict] = []

        # ── Service nodes ───────────────────────────────────────────────
        for svc_id, svc in self.services.items():
            layer_def = LAYERS.get(svc.layer)
            color = layer_def.color if layer_def else '#95A5A6'
            icon = layer_def.icon if layer_def else '🔧'

            # Размер = кол-во потребителей + зависимостей
            total_connections = len(svc.consumers) + len(svc.dependencies)
            size = max(22, min(55, 18 + total_connections * 3))

            # Добавляем уровень для hierarchical layout
            level = layer_def.order if layer_def else 2

            border_color = '#E74C3C' if svc.is_critical else color
            border_width = 3 if svc.is_critical else 1

            title_lines = [
                f'Сервис: {svc.name}',
                f'Слой: {LAYERS.get(svc.layer, ServiceLayer(svc.layer, svc.layer, "#999", 0, "", "")).name}',
                f'IP: {", ".join(svc.ips) if svc.ips else "—"}',
                f'Порты: {", ".join(str(p) for p in svc.ports) if svc.ports else "—"}',
                f'Зависимости: {len(svc.dependencies)}',
                f'Потребители: {len(svc.consumers)}',
                f'Риск: {svc.risk_score:.1f}/10',
            ]
            if svc.is_critical:
                title_lines.append('⚠️ КРИТИЧНЫЙ СЕРВИС')

            nodes.append({
                'id': svc_id,
                'label': f'{icon} {svc.name}',
                'group': svc.layer,
                'layer': svc.layer,
                'level': level,
                'color': color,
                'size': size,
                'borderWidth': border_width,
                'borderWidthSelected': border_width + 2,
                'shape': 'box' if svc.layer == 'data' else 'dot',
                'title': '\n'.join(title_lines),
                'font': {'color': '#fff' if svc.layer in ('external', 'infrastructure') else '#333'},
            })

        # ── Service edges ───────────────────────────────────────────────
        for edge in self.edges:
            from_svc = self.services.get(edge.from_service)
            to_svc = self.services.get(edge.to_service)
            if not from_svc or not to_svc:
                continue

            # Цвет ребра по риску
            if edge.risk_score >= 7:
                edge_color = '#E74C3C'
            elif edge.risk_score >= 4:
                edge_color = '#F39C12'
            else:
                edge_color = '#3498DB'

            # Ширина ребра
            width = 1 + edge.rules_count
            if width > 6:
                width = 6

            # Подпись портов
            port_label = ', '.join(str(p) for p in edge.ports[:3]) if edge.ports else ''
            if len(edge.ports) > 3:
                port_label += f'+{len(edge.ports) - 3}'

            label = f'{edge.protocol.upper()}'
            if port_label:
                label += f' :{port_label}'

            title = (
                f'{from_svc.name} → {to_svc.name}\n'
                f'Протокол: {edge.protocol.upper()}\n'
                f'Порты: {port_label or "—"}\n'
                f'Действие: {edge.action}\n'
                f'Правил: {edge.rules_count}\n'
                f'Риск: {edge.risk_score:.1f}/10'
            )

            edges.append({
                'from': edge.from_service,
                'to': edge.to_service,
                'label': label,
                'color': {'color': edge_color},
                'width': width,
                'arrows': 'to',
                'dashes': edge.action == 'deny',
                'smooth': {'type': 'cubicBezier'},
                'title': title,
            })

        return nodes, edges

    # ── Dependency matrix ───────────────────────────────────────────────

    def get_service_matrix(self) -> Dict:
        """
        Матрица зависимостей сервисов.

        Формат:
        {
            "layers": {...},
            "services": [...],
            "matrix": {svc_id_from: {svc_id_to: info}}
        }
        """
        services_list = []
        for svc_id, svc in self.services.items():
            services_list.append({
                'id': svc_id,
                'name': svc.name,
                'layer': svc.layer,
                'ips': svc.ips,
                'ports': svc.ports,
                'dependencies': len(svc.dependencies),
                'consumers': len(svc.consumers),
                'is_critical': svc.is_critical,
                'risk_score': svc.risk_score,
            })

        matrix = {}
        for from_id, from_svc in self.services.items():
            matrix[from_id] = {}
            for to_id, to_svc in self.services.items():
                # Ищем рёбра
                matched = [e for e in self.edges
                          if e.from_service == from_id and e.to_service == to_id]

                if matched:
                    max_risk = max(e.risk_score for e in matched)
                    total_rules = sum(e.rules_count for e in matched)
                    all_ports = list({p for e in matched for p in e.ports})
                    matrix[from_id][to_id] = {
                        'risk': max_risk,
                        'rules_count': total_rules,
                        'ports': all_ports[:5],
                    }
                else:
                    matrix[from_id][to_id] = None

        return {
            'layers': {
                k: {'name': v.name, 'color': v.color, 'order': v.order, 'icon': v.icon}
                for k, v in LAYERS.items()
            },
            'services': services_list,
            'matrix': matrix,
            'edges_count': len(self.edges),
        }

    # ── Summary ─────────────────────────────────────────────────────────

    def summary(self) -> Dict:
        """Сводная статистика сервисной топологии."""
        services_by_layer = defaultdict(list)
        for svc in self.services.values():
            services_by_layer[svc.layer].append(svc.name)

        critical_svcs = [s.name for s in self.services.values() if s.is_critical]

        return {
            'services_count': len(self.services),
            'edges_count': len(self.edges),
            'services_by_layer': {
                layer: {
                    'name': LAYERS[layer].name,
                    'count': len(services_by_layer[layer]),
                    'services': services_by_layer[layer],
                }
                for layer in LAYERS
                if services_by_layer[layer]
            },
            'critical_services': critical_svcs,
            'critical_count': len(critical_svcs),
            'high_risk_edges': sum(1 for e in self.edges if e.risk_score >= 7),
            'external_dependencies': sum(
                1 for s in self.services.values() if s.layer == 'external'
            ),
        }

    # ── Filters ─────────────────────────────────────────────────────────

    def get_services_by_layer(self, layer: str) -> List[ServiceNode]:
        """Возвращает сервисы определённого слоя."""
        return [s for s in self.services.values() if s.layer == layer]

    def get_critical_services(self) -> List[ServiceNode]:
        """Возвращает только критические сервисы."""
        return [s for s in self.services.values() if s.is_critical]


# ─── CLI integration ───────────────────────────────────────────────────────

def build_service_topology(
    rules,
    manual_services: Optional[Dict] = None,
) -> Tuple[List[Dict], List[Dict], ServiceTopologyBuilder]:
    """
    Точка входа: строит Service/App Topology.

    Принимает:
    - rules: список FirewallRule (из парсера)
    - manual_services: опциональный словарь для ручной регистрации:
      {name: {layer, ips, ports, description}}

    Возвращает (nodes, edges, builder) — nodes/edges для Vis.js + builder для
    дополнительных запросов (matrix, summary, фильтрация).

    Использование:
        from src.core.service_topology import build_service_topology
        nodes, edges, builder = build_service_topology(rules)
    """
    builder = ServiceTopologyBuilder()

    # 1. Ручная регистрация сервисов (если задана)
    if manual_services:
        for svc_name, svc_info in manual_services.items():
            svc_id = builder.register_service(
                name=svc_name,
                layer=svc_info.get('layer'),
                ips=svc_info.get('ips', []),
                ports=svc_info.get('ports', []),
                description=svc_info.get('description', ''),
            )
            # Ручные зависимости
            for dep in svc_info.get('depends_on', []):
                # dep = (target_svc_name, protocol, port)
                # Найдём target по имени
                pass  # реализуется если нужно

    # 2. Извлекаем сервисы из правил
    extracted = builder.extract_services_from_rules(rules)

    # 3. Считаем статистику и выводим
    stats = builder.summary()

    print(f"[Service Topology] {stats['services_count']} сервисов, "
          f"{stats['edges_count']} зависимостей")

    for layer_key, layer_info in stats['services_by_layer'].items():
        print(f"  {layer_info['name']}: {layer_info['count']} сервисов")
        if layer_info['services']:
            print(f"    → {', '.join(layer_info['services'][:5])}"
                  f'{"…" if len(layer_info["services"]) > 5 else ""}')

    if stats['critical_services']:
        print(f"  ⚠️ Критичные сервисы ({stats['critical_count']}): "
              f"{', '.join(stats['critical_services'])}")

    if stats['high_risk_edges']:
        print(f"  🔴 Высокорисковых зависимостей: {stats['high_risk_edges']}")

    if stats['external_dependencies']:
        print(f"  🌍 Внешних зависимостей: {stats['external_dependencies']}")

    # 4. Экспортируем Vis.js
    nodes, edges = builder.to_visjs()
    return nodes, edges, builder


# Экспорт
__all__ = [
    'ServiceLayer',
    'ServiceNode',
    'ServiceEdge',
    'ServiceTopologyBuilder',
    'build_service_topology',
    'LAYERS',
    'PORT_LAYER_MAP',
    'NAME_LAYER_HINTS',
]
