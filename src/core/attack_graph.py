"""
Модуль построения графа атак (Attack Graph / Attack Path Simulation).

Выявляет external-facing узлы, критические активы и строит BFS-пути
от внешних зон к критическим активам с учётом ACL-ограничений.
"""

from collections import deque
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field

import networkx as nx

from ..models.rule import FirewallRule


# ─── Зоны ────────────────────────────────────────────────────────

EXTERNAL_ZONES = {'internet', 'external', 'untrusted', 'wan', 'public'}
CRITICAL_ZONES = {'management', 'critical', 'trusted'}

# Имена узлов, которые всегда считаются внешними (независимо от zone-атрибута)
EXTERNAL_NODE_NAMES = {
    'internet', 'external', 'wan', 'public', 'outside', 'untrusted',
    'internet_zone', 'internet zone',
}

# Имена узлов, которые считаются критическими (по названию)
CRITICAL_NODE_KEYWORDS = {
    'management', 'admin', 'critical', 'trusted', 'secure',
    'dc', 'domain controller', 'ad', 'active directory',
    'db', 'database', 'sql',
    'bastion', 'jump',
}

# Критические порты/сервисы, повышающие ценность цели
CRITICAL_PORTS = {
    22: 'SSH', 3389: 'RDP', 53: 'DNS', 88: 'Kerberos', 389: 'LDAP',
    1433: 'MSSQL', 3306: 'MySQL', 5432: 'PostgreSQL',
    1521: 'Oracle', 27017: 'MongoDB', 6379: 'Redis',
    135: 'RPC', 445: 'SMB', 636: 'LDAPS', 3268: 'AD-GC',
    5985: 'WinRM', 5986: 'WinRM-SSL',
}

# Порты, характерные для DB / DC / Admin
CRITICAL_PORT_KEYWORDS = {
    'db': {1433, 3306, 5432, 1521, 27017, 6379, 9200},
    'dc': {53, 88, 389, 135, 445, 636, 3268, 3269},
    'admin': {22, 3389, 5985, 5986, 80, 443, 8080, 8443},
}


# ─── Data-классы ─────────────────────────────────────────────────

@dataclass
class AttackHop:
    """Один шаг (хоп) в пути атаки."""
    node: str
    rule: Optional[str]  # имя правила, разрешающего переход
    risk: int            # 0-10


@dataclass
class AttackPath:
    """Полный путь атаки от источника до цели."""
    source: str
    target: str
    hops: List[AttackHop]
    risk_score: int      # агрегированный риск пути
    reachable: bool      # достигнута ли цель


@dataclass
class AttackGraphResult:
    """Результат анализа графа атак."""
    attack_paths: List[AttackPath]
    sources_count: int
    targets_count: int
    reachable_targets: int
    external_sources: List[str] = field(default_factory=list)
    critical_targets: List[str] = field(default_factory=list)


# ─── Вспомогательные функции ────────────────────────────────────

def _normalize_zone(zone: Optional[str]) -> str:
    """Нормализует название зоны."""
    if not zone:
        return 'unknown'
    return zone.strip().lower()


def _is_external_zone(zone: str) -> bool:
    """Является ли зона внешней (Internet-facing)."""
    z = _normalize_zone(zone)
    return any(ext in z for ext in EXTERNAL_ZONES)


def _is_critical_zone(zone: str) -> bool:
    """Является ли зона критической."""
    z = _normalize_zone(zone)
    return any(crit in z for crit in CRITICAL_ZONES)


def _node_has_critical_port(ports: Set[int]) -> bool:
    """Проверяет, есть ли у узла критические порты."""
    if not ports:
        return False
    return bool(ports & set(CRITICAL_PORTS.keys()))


def _port_criticality_level(ports: Set[int]) -> str:
    """
    Возвращает уровень критичности на основе портов:
    'critical' — DC/DB порты, 'high' — admin порты, 'medium' — остальные критические.
    """
    if not ports:
        return 'low'
    all_dc_db = CRITICAL_PORT_KEYWORDS['db'] | CRITICAL_PORT_KEYWORDS['dc']
    if ports & all_dc_db:
        return 'critical'
    if ports & CRITICAL_PORT_KEYWORDS['admin']:
        return 'high'
    return 'medium'


def _risk_from_zone_gap(src_zone: str, dst_zone: str) -> int:
    """Оценивает риск перехода между зонами (1-5)."""
    src = _normalize_zone(src_zone)
    dst = _normalize_zone(dst_zone)
    if _is_external_zone(src) and _is_critical_zone(dst):
        return 5
    if _is_external_zone(src):
        return 4
    if _is_critical_zone(dst):
        return 3
    return 2


def _build_edge_acl(graph: nx.DiGraph, rules: List[FirewallRule]) -> Dict[Tuple[str, str], List[Dict]]:
    """
    Строит ACL-таблицу для рёбер графа:
    {(src, dst): [{'rule': name, 'action': accept/deny, 'services': set, 'risk': int}, ...]}
    """
    acl: Dict[Tuple[str, str], List[Dict]] = {}

    for rule in rules:
        if not rule.enabled:
            continue
        for src_ep in rule.sources:
            src_name = src_ep.name
            for dst_ep in rule.destinations:
                dst_name = dst_ep.name
                key = (src_name, dst_name)
                if key not in acl:
                    acl[key] = []
                svc_ports: Set[int] = set()
                for svc in rule.services:
                    svc_ports.update(svc.ports if svc.ports else set())
                acl[key].append({
                    'rule': rule.name,
                    'action': rule.action,
                    'services': svc_ports,
                    'risk': 5,  # base risk, will be adjusted
                })

    return acl


class AttackGraphBuilder:
    """
    Построитель графа атак.
    Выполняет BFS от external узлов до critical assets с учётом ACL.
    """

    MAX_HOPS = 5

    def __init__(self, graph: nx.DiGraph, rules: List[FirewallRule]):
        self.graph = graph
        self.rules = rules
        self.acl = _build_edge_acl(graph, rules)
        self._external_sources: List[str] = []
        self._critical_targets: List[str] = []

    def detect_external_sources(self) -> List[str]:
        """
        Находит все external-facing узлы.

        Использует несколько признаков:
        1. Атрибут zone = external-зона (internet/external/untrusted/wan/public)
        2. Имя узла совпадает с EXTERNAL_NODE_NAMES
        3. CIDR 0.0.0.0/0 (весь интернет)
        4. Узел типа 'zone' с external-зоной
        """
        sources = []
        for node, data in self.graph.nodes(data=True):
            node_name = str(node).strip().lower()
            zone = _normalize_zone(data.get('zone', ''))
            etype = data.get('endpoint_type', '').lower()
            cidrs = data.get('cidrs', [])

            # 1. Zone attribute
            if zone and _is_external_zone(zone):
                sources.append(str(node))
                continue

            # 2. Node name matches external keywords
            if node_name in EXTERNAL_NODE_NAMES or any(
                ext in node_name for ext in ('internet', 'external', 'wan', 'untrusted')
            ):
                sources.append(str(node))
                continue

            # 3. CIDR 0.0.0.0/0
            if any(str(c).strip() == '0.0.0.0/0' for c in cidrs):
                sources.append(str(node))
                continue

            # 4. Zone-type node in external zone (checked above, but fallback)
            if etype == 'zone' and _is_external_zone(node_name):
                sources.append(str(node))
                continue

        self._external_sources = sources
        return sources

    def detect_critical_assets(self) -> List[str]:
        """
        Находит критические активы (зоны + порты + имена).

        Использует несколько признаков:
        1. Атрибут zone = critical-зона (management/critical/trusted)
        2. Имя узла содержит critical-ключевые слова (dc, db, management, etc.)
        3. Критические порты (SSH, RDP, DB-порты и т.д.)
        4. Узел типа 'zone' с critical-зоной
        5. Узел, в который приходит много входящих рёбер (хаб) — потенциально критический
        """
        targets = []
        already_targeted: Set[str] = set()

        for node, data in self.graph.nodes(data=True):
            node_name = str(node).strip().lower()
            zone = _normalize_zone(data.get('zone', ''))
            etype = data.get('endpoint_type', '').lower()
            ports = data.get('ports', set())
            if isinstance(ports, list):
                ports = set(ports)

            level = _port_criticality_level(ports)
            is_critical = False

            # 1. Zone attribute
            if zone and _is_critical_zone(zone):
                is_critical = True

            # 2. Node name keywords
            if not is_critical:
                for kw in CRITICAL_NODE_KEYWORDS:
                    if kw in node_name:
                        is_critical = True
                        break

            # 3. Critical ports
            if not is_critical and level in ('critical', 'high'):
                is_critical = True

            # 4. Zone-type node
            if not is_critical and etype == 'zone' and _is_critical_zone(node_name):
                is_critical = True

            if is_critical and str(node) not in already_targeted:
                targets.append(str(node))
                already_targeted.add(str(node))

        # 5. Fallback: nodes reachable from external sources become targets
        #    (any node connected to or from external sources is interesting)
        if not targets:
            # Nodes with high in-degree (multiple inbound connections) = likely servers
            in_degrees = {}
            for _, dst in self.graph.edges():
                in_degrees[dst] = in_degrees.get(dst, 0) + 1
            if in_degrees:
                sorted_by_in = sorted(in_degrees.items(), key=lambda x: -x[1])
                threshold = max(2, sorted_by_in[0][1] // 2) if sorted_by_in else 2
                for node_str, deg in sorted_by_in:
                    if deg >= threshold and str(node_str) not in already_targeted:
                        targets.append(str(node_str))
                        already_targeted.add(str(node_str))

        self._critical_targets = targets
        return targets

    def _edge_allowed(self, src: str, dst: str) -> Tuple[bool, Optional[str], int, str]:
        """
        Проверяет, разрешён ли переход src→dst по ACL.
        Возвращает (allowed, rule_name, risk, service_info).
        """
        key = (src, dst)
        entries = self.acl.get(key, [])
        if not entries:
            # Если ACL нет, проверяем наличие ребра в графе
            if self.graph.has_edge(src, dst):
                edge_data = self.graph[src][dst]
                risk = edge_data.get('risk_score', 3)
                rules_list = edge_data.get('rules', [])
                rule_name = rules_list[0] if rules_list else None
                services = edge_data.get('services', [])
                service_info = ', '.join(services[:3]) if services else ''
                return True, rule_name, risk, service_info
            return False, None, 0, ''

        # Ищем разрешающее правило (первое подходящее)
        for entry in entries:
            if entry['action'] in ('accept', 'permit', 'allow'):
                svc_ports = entry.get('services', set())
                svc_info = ', '.join(str(p) for p in list(svc_ports)[:3]) if svc_ports else ''
                return True, entry['rule'], entry['risk'], svc_info
        return False, None, 0, ''

    def _estimate_hop_risk(self, src: str, dst: str) -> int:
        """Оценивает риск одного хопа на основе данных графа."""
        risk = 3  # base
        src_data = self.graph.nodes.get(src, {})
        dst_data = self.graph.nodes.get(dst, {})
        src_zone = _normalize_zone(src_data.get('zone', ''))
        dst_zone = _normalize_zone(dst_data.get('zone', ''))
        risk = _risk_from_zone_gap(src_zone, dst_zone)
        # Увеличиваем риск если у dst критические порты
        dst_ports = dst_data.get('ports', set())
        if isinstance(dst_ports, list):
            dst_ports = set(dst_ports)
        if _node_has_critical_port(dst_ports):
            risk = min(10, risk + 2)
        return risk

    def _bfs_attack_paths(self, max_hops: int = MAX_HOPS) -> List[AttackPath]:
        """
        BFS от каждого external источника ко всем достижимым узлам.
        Все достижимые узлы считаются потенциальными целями.
        Возвращает все найденные пути длиной ≤ max_hops.
        """
        paths: List[AttackPath] = []
        sources = self._external_sources or self.detect_external_sources()
        critical_set = set(self._critical_targets or self.detect_critical_assets())

        if not sources:
            return paths

        # Все узлы, кроме самих external источников — потенциальные цели
        all_nodes = set(self.graph.nodes()) | {k[0] for k in self.acl} | {k[1] for k in self.acl}
        all_targets = all_nodes - set(sources)

        if not all_targets:
            return paths

        for source in sources:
            # BFS queue
            queue: deque = deque()
            visited: Set[str] = {source}
            parent_map: Dict[str, Tuple[str, Optional[str], int, str]] = {}
            depth_map: Dict[str, int] = {source: 0}

            queue.append(source)

            while queue:
                current = queue.popleft()
                current_depth = depth_map.get(current, 0)

                # Don't go beyond max hops
                if current_depth >= max_hops:
                    continue

                # Get neighbors
                neighbors = set()
                if self.graph.has_node(current):
                    for _, dst in self.graph.out_edges(current):
                        neighbors.add(dst)
                for (s, d) in self.acl:
                    if s == current:
                        neighbors.add(d)

                for neighbor in neighbors:
                    if neighbor in visited:
                        continue
                    allowed, rule_name, risk, svc_info = self._edge_allowed(current, neighbor)
                    if not allowed:
                        continue
                    visited.add(neighbor)
                    parent_map[neighbor] = (current, rule_name, risk, svc_info)
                    depth_map[neighbor] = current_depth + 1
                    queue.append(neighbor)

            # Build paths to all reachable targets
            for target in all_targets & visited:
                if target == source:
                    continue
                path = self._reconstruct_path(source, target, parent_map)
                if path and len(path.hops) <= max_hops + 1:
                    # Mark whether the target is critical
                    path.risk_score += (3 if target in critical_set else 0)
                    paths.append(path)

        # Sort: critical targets first, then by risk score
        paths.sort(key=lambda p: (
            0 if p.target in critical_set else 1,
            -p.risk_score
        ))

        return paths

    def _reconstruct_path(self, source: str, target: str,
                          parent_map: Dict[str, Tuple[str, Optional[str], int, str]]) -> Optional[AttackPath]:
        """Восстанавливает путь от source к target по parent_map."""
        hops: List[AttackHop] = []
        current = target
        total_risk = 0
        services_along_path: List[str] = []

        while current != source:
            if current not in parent_map:
                return None
            parent, rule, risk, svc_info = parent_map[current]
            hop_risk = risk if risk else self._estimate_hop_risk(parent, current)
            hop_label = f"{current}"
            if svc_info:
                hop_label = f"{current} [{svc_info}]"
            if rule:
                hop_label = f"{current} [{rule}]"
            hops.append(AttackHop(
                node=hop_label,
                rule=rule,
                risk=hop_risk,
            ))
            total_risk += hop_risk
            if svc_info:
                services_along_path.append(svc_info)
            current = parent

        # Добавляем source как первый хоп
        hops.append(AttackHop(
            node=source,
            rule=None,
            risk=0,
        ))
        hops.reverse()

        # Нормализуем риск
        avg_risk = min(10, int(total_risk / max(1, len(hops) - 1))) if len(hops) > 1 else 0

        return AttackPath(
            source=source,
            target=target,
            hops=hops,
            risk_score=avg_risk,
            reachable=True,
        )

    def build_attack_graph(self, max_hops: int = MAX_HOPS) -> AttackGraphResult:
        """
        Основной метод: строит полный граф атак.

        Returns:
            AttackGraphResult со всеми найденными путями атак.
        """
        self.detect_external_sources()
        self.detect_critical_assets()

        attack_paths = self._bfs_attack_paths(max_hops)

        # Определяем reachable_targets
        reachable = set(p.target for p in attack_paths if p.reachable)

        # Сортируем пути по риску (наиболее опасные первыми)
        attack_paths.sort(key=lambda p: p.risk_score, reverse=True)

        return AttackGraphResult(
            attack_paths=attack_paths,
            sources_count=len(self._external_sources),
            targets_count=len(self._critical_targets),
            reachable_targets=len(reachable),
            external_sources=list(self._external_sources),
            critical_targets=list(self._critical_targets),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Экспорт результата в словарь для JSON-сериализации."""
        result = self.build_attack_graph()
        return {
            'attack_paths': [
                {
                    'source': p.source,
                    'target': p.target,
                    'riskscore': p.risk_score,
                    'reachable': p.reachable,
                    'hops': [
                        {
                            'node': h.node,
                            'rule': h.rule,
                            'risk': h.risk,
                        }
                        for h in p.hops
                    ],
                    'hop_count': len(p.hops),
                }
                for p in result.attack_paths
            ],
            'sources_count': result.sources_count,
            'targets_count': result.targets_count,
            'reachable_targets': result.reachable_targets,
            'external_sources': result.external_sources,
            'critical_targets': result.critical_targets,
            'max_hops': self.MAX_HOPS,
        }
