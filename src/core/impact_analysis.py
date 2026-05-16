"""
A2 — Impact Analysis Engine

Обратный граф зависимостей, каскадное влияние изменений,
классификация severity, текстовые и JSON отчёты.
"""

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLORS = {
    "critical": "#e94560",
    "high": "#f59e0b",
    "medium": "#3b82f6",
    "low": "#10b981",
}


@dataclass
class DependencyNode:
    """Узел в графе зависимостей."""
    node_id: str
    node_type: str  # "rule" or "host" or "service" or "zone"
    label: str
    dependencies: Set[str] = field(default_factory=set)  # кто зависит от этого узла

    @property
    def dependency_count(self) -> int:
        return len(self.dependencies)


@dataclass
class DependencyGraph:
    """Обратный граф: кто зависит от каждого узла/правила."""
    nodes: Dict[str, DependencyNode] = field(default_factory=dict)
    # Прямые рёбра: node_id -> [dependent_ids]
    reverse_edges: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))

    def add_node(self, node_id: str, node_type: str, label: str):
        if node_id not in self.nodes:
            self.nodes[node_id] = DependencyNode(
                node_id=node_id, node_type=node_type, label=label
            )

    def add_dependency(self, from_id: str, to_id: str):
        """from_id зависит от to_id (to_id → from_id в обратном графе)."""
        self.reverse_edges[to_id].add(from_id)
        if to_id in self.nodes:
            self.nodes[to_id].dependencies.add(from_id)

    def get_dependents(self, node_id: str) -> Set[str]:
        """Кто зависит от node_id (прямые)."""
        return self.reverse_edges.get(node_id, set())

    def get_all_dependents(self, node_id: str, visited: Optional[Set[str]] = None) -> Set[str]:
        """Все транзитивные зависимости (каскад)."""
        if visited is None:
            visited = set()
        if node_id in visited:
            return set()
        visited.add(node_id)

        result: Set[str] = set()
        for dep in self.get_dependents(node_id):
            result.add(dep)
            result.update(self.get_all_dependents(dep, visited))
        return result

    def find_critical_paths(self, node_id: str) -> List[List[str]]:
        """Находит все критические пути из node_id до листьев."""
        paths: List[List[str]] = []

        def dfs(current: str, path: List[str], visited: Set[str]):
            if current in visited:
                return
            visited.add(current)
            new_path = path + [current]
            deps = self.get_dependents(current)
            if not deps:
                paths.append(new_path)
            else:
                for dep in deps:
                    dfs(dep, new_path, visited.copy())

        dfs(node_id, [], set())
        return paths


@dataclass
class AffectedEntity:
    """Сущность, затронутая изменением."""
    entity_id: str
    entity_type: str  # host, service, zone, rule
    label: str
    severity: str  # critical/high/medium/low
    reason: str


@dataclass
class CascadingImpact:
    """Результат анализа каскадного влияния."""
    target_id: str
    target_type: str
    target_label: str
    direct_impact: List[AffectedEntity]
    cascading_impact: List[AffectedEntity]
    critical_paths: List[List[str]]
    overall_severity: str
    affected_count: int
    affected_services: List[str]
    affected_hosts: List[str]
    affected_zones: List[str]
    affected_rules: List[str]


@dataclass
class ImpactReport:
    """Текстовый отчёт анализа влияния."""
    summary: str
    direct_section: str
    cascading_section: str
    recommendations: List[str]


class ImpactAnalyzer:
    """Анализатор влияния изменений в конфигурации межсетевого экрана."""

    def __init__(
        self,
        nodes_data: List[Dict],
        edges_data: List[Dict],
        rules_data: List[Dict],
    ):
        self.nodes_data = nodes_data
        self.edges_data = edges_data
        self.rules_data = rules_data
        self.graph = DependencyGraph()

        # Справочники
        self._node_index: Dict[str, Dict] = {}
        self._zone_nodes: Dict[str, List[str]] = defaultdict(list)
        self._build_indices()

    def _build_indices(self):
        """Строит индексы и граф зависимостей."""
        for node in self.nodes_data:
            nid = node.get("id", "")
            gtype = node.get("type", "unknown")
            label = node.get("label", nid)
            zone = node.get("group", node.get("zone", "unknown"))
            self._node_index[nid] = node
            self.graph.add_node(nid, gtype, label)
            self._zone_nodes[zone].append(nid)

        # Добавляем правила как узлы
        for rule in self.rules_data:
            rname = rule.get("name", "unknown")
            self.graph.add_node(rname, "rule", rname)

        # Строим зависимости из рёбер
        for edge in self.edges_data:
            src = edge.get("from", "")
            dst = edge.get("to", "")
            if src and dst:
                # dst зависит от src (трафик идёт src→dst)
                self.graph.add_node(src, "host", src)
                self.graph.add_node(dst, "host", dst)
                self.graph.add_dependency(src, dst)

        # Правила зависят от узлов, которые они упоминают
        for rule in self.rules_data:
            rname = rule.get("name", "unknown")
            sources = rule.get("sources", "")
            dests = rule.get("destinations", "")
            services = rule.get("services", "")

            for src_name in sources.split(", "):
                src_name = src_name.strip()
                if src_name and src_name in self._node_index:
                    self.graph.add_dependency(src_name, rname)

            for dst_name in dests.split(", "):
                dst_name = dst_name.strip()
                if dst_name and dst_name in self._node_index:
                    self.graph.add_dependency(dst_name, rname)

    def _classify_severity(self, entity_id: str, entity_type: str, dep_count: int) -> str:
        """Классифицирует severity по контексту."""
        if entity_type == "rule":
            # Правила, от которых зависит много узлов
            if dep_count >= 10:
                return "critical"
            elif dep_count >= 5:
                return "high"
            elif dep_count >= 2:
                return "medium"
            return "low"

        # Для узлов: проверяем зону и тип
        node = self._node_index.get(entity_id, {})
        zone = node.get("group", node.get("zone", "")).lower()
        ntype = node.get("type", "unknown")

        # Core infrastructure
        core_keywords = ["core", "backbone", "management", "mgmt", "admin"]
        critical_services = ["db", "database", "auth", "ldap", "dns", "ntp"]

        if any(kw in zone for kw in core_keywords):
            return "critical"
        if any(kw in entity_id.lower() for kw in critical_services):
            return "high"
        if dep_count >= 10:
            return "critical"
        elif dep_count >= 5:
            return "high"
        elif dep_count >= 2:
            return "medium"
        return "low"

    def analyze(self, target_type: str, target_id: str) -> CascadingImpact:
        """Анализирует влияние изменения/удаления target."""
        # Find target label
        target_label = target_id
        if target_type == "rule":
            for rule in self.rules_data:
                if rule.get("name") == target_id:
                    target_label = target_id
                    break
        else:
            node = self._node_index.get(target_id, {})
            target_label = node.get("label", target_id)

        # Direct dependents
        direct_deps = self.graph.get_dependents(target_id)
        # Cascading (transitive)
        all_deps = self.graph.get_all_dependents(target_id)

        direct_impact: List[AffectedEntity] = []
        for dep_id in sorted(direct_deps):
            dep_node = self.graph.nodes.get(dep_id)
            dep_type = dep_node.node_type if dep_node else "unknown"
            dep_label = dep_node.label if dep_node else dep_id
            dep_count = len(self.graph.get_dependents(dep_id))
            severity = self._classify_severity(dep_id, dep_type, dep_count)

            direct_impact.append(AffectedEntity(
                entity_id=dep_id,
                entity_type=dep_type,
                label=dep_label,
                severity=severity,
                reason=f"Прямая зависимость от {target_label}",
            ))

        cascading_impact: List[AffectedEntity] = []
        cascade_only = all_deps - direct_deps
        for dep_id in sorted(cascade_only):
            dep_node = self.graph.nodes.get(dep_id)
            dep_type = dep_node.node_type if dep_node else "unknown"
            dep_label = dep_node.label if dep_node else dep_id
            dep_count = len(self.graph.get_dependents(dep_id))
            severity = self._classify_severity(dep_id, dep_type, dep_count)

            cascading_impact.append(AffectedEntity(
                entity_id=dep_id,
                entity_type=dep_type,
                label=dep_label,
                severity=severity,
                reason=f"Каскадная зависимость (транзитивно от {target_label})",
            ))

        # Critical paths
        critical_paths = self.graph.find_critical_paths(target_id)

        # Aggregate: collect all affected grouped by type
        all_affected = direct_impact + cascading_impact
        affected_services = []
        affected_hosts = []
        affected_zones = []
        affected_rules = []

        for ae in all_affected:
            if ae.entity_type == "rule":
                affected_rules.append(ae.label)
            elif ae.entity_type == "host":
                affected_hosts.append(ae.label)
            elif ae.entity_type in ("zone",):
                affected_zones.append(ae.label)
            else:
                affected_services.append(ae.label)

        # Overall severity: max of all affected
        overall = "low"
        for ae in all_affected:
            if SEVERITY_ORDER.get(ae.severity, 99) < SEVERITY_ORDER.get(overall, 99):
                overall = ae.severity

        return CascadingImpact(
            target_id=target_id,
            target_type=target_type,
            target_label=target_label,
            direct_impact=direct_impact,
            cascading_impact=cascading_impact,
            critical_paths=critical_paths,
            overall_severity=overall,
            affected_count=len(all_affected),
            affected_services=affected_services,
            affected_hosts=affected_hosts,
            affected_zones=affected_zones,
            affected_rules=affected_rules,
        )

    def impact_report(self, target_type: str, target_id: str) -> ImpactReport:
        """Генерирует текстовый отчёт анализа влияния."""
        impact = self.analyze(target_type, target_id)

        # Summary
        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        summary_lines = [
            f"{'='*60}",
            f"  IMPACT ANALYSIS REPORT",
            f"{'='*60}",
            f"",
            f"Target: {impact.target_label} ({impact.target_type})",
            f"Overall Severity: {sev_emoji.get(impact.overall_severity, '⚪')} {impact.overall_severity.upper()}",
            f"Total Affected: {impact.affected_count} entities",
            f"",
            f"Direct Impact: {len(impact.direct_impact)} entities",
            f"Cascading Impact: {len(impact.cascading_impact)} entities",
            f"",
        ]
        summary = "\n".join(summary_lines)

        # Direct section
        direct_lines = ["DIRECT IMPACT:", "-" * 40]
        for ae in impact.direct_impact:
            direct_lines.append(
                f"  [{ae.severity.upper():8}] {ae.entity_type:6} | {ae.label:40} | {ae.reason}"
            )
        direct_section = "\n".join(direct_lines)

        # Cascading section
        casc_lines = ["", "CASCADING IMPACT:", "-" * 40]
        for ae in impact.cascading_impact:
            casc_lines.append(
                f"  [{ae.severity.upper():8}] {ae.entity_type:6} | {ae.label:40} | {ae.reason}"
            )
        cascading_section = "\n".join(casc_lines)

        # Recommendations
        recommendations = []
        if impact.overall_severity in ("critical", "high"):
            recommendations.append(
                "⚠️  ВНИМАНИЕ: изменение имеет высокий/критический уровень влияния. "
                "Рекомендуется согласование с командой безопасности."
            )
        if len(impact.critical_paths) > 3:
            recommendations.append(
                "🔀 Обнаружено множество критических путей. Рекомендуется провести "
                "поэтапное внедрение изменений с мониторингом."
            )
        if impact.affected_rules:
            recommendations.append(
                f"📋 Затронуто {len(impact.affected_rules)} правил. "
                "Проверьте корректность правил после внесения изменений."
            )
        if impact.affected_hosts:
            recommendations.append(
                f"🖥️  Затронуто {len(impact.affected_hosts)} хостов. "
                "Убедитесь что сервисы на этих хостах продолжат работать."
            )
        if not recommendations:
            recommendations.append(
                "✅ Низкий уровень влияния. Изменения можно вносить в стандартном режиме."
            )

        return ImpactReport(
            summary=summary,
            direct_section=direct_section,
            cascading_section=cascading_section,
            recommendations=recommendations,
        )

    def impact_json(self, target_type: str, target_id: str) -> Dict[str, Any]:
        """Возвращает результат в JSON-формате для UI."""
        impact = self.analyze(target_type, target_id)

        def entity_to_dict(ae: AffectedEntity) -> Dict[str, Any]:
            return {
                "id": ae.entity_id,
                "type": ae.entity_type,
                "label": ae.label,
                "severity": ae.severity,
                "reason": ae.reason,
                "color": SEVERITY_COLORS.get(ae.severity, "#6b7280"),
            }

        return {
            "target": {
                "id": impact.target_id,
                "type": impact.target_type,
                "label": impact.target_label,
            },
            "overall_severity": impact.overall_severity,
            "severity_color": SEVERITY_COLORS.get(impact.overall_severity, "#6b7280"),
            "affected_count": impact.affected_count,
            "direct_impact": [entity_to_dict(ae) for ae in impact.direct_impact],
            "cascading_impact": [entity_to_dict(ae) for ae in impact.cascading_impact],
            "critical_paths": impact.critical_paths,
            "summary": {
                "services": impact.affected_services,
                "hosts": impact.affected_hosts,
                "zones": impact.affected_zones,
                "rules": impact.affected_rules,
            },
        }
